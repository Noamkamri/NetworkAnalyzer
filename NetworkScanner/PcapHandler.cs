using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using static NetworkScanner.PacketScanner;

namespace NetworkScanner
{
    public static class PcapHandler
    {
        // ─── Constants ────────────────────────────────────────────────────────────

        private const uint   PcapMagicNumber  = 0xa1b2c3d4;
        private const short  PcapMajorVersion = 2;
        private const short  PcapMinorVersion = 4;
        private const int    PcapSnapLen      = 65535;
        private const int    PcapNetworkEthernet = 1;

        private const ushort EtherTypeIPv4    = 0x0800;
        private const int    EthernetHeaderSize = 14;
        private const int    IPv4HeaderSize    = 20;
        private const int    MinFrameSize      = EthernetHeaderSize + IPv4HeaderSize;

        private const byte   ProtocolTCP      = 6;
        private const byte   ProtocolUDP      = 17;
        private const byte   DefaultTTL       = 64;
        private const int    DefaultLength    = 60;

        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // ─── Public API ───────────────────────────────────────────────────────────

        public static void SaveToPcap(string filePath, List<PacketInfo> packets)
        {
            using var fs     = new FileStream(filePath, FileMode.Create);
            using var writer = new BinaryWriter(fs);

            WriteGlobalHeader(writer);

            foreach (var packet in packets)
            {
                byte[] frame = BuildFrame(packet);
                WritePacketHeader(writer, packet.Timestamp, frame.Length);
                writer.Write(frame);
            }
        }

        public static List<PacketInfo> LoadFromPcap(string filePath)
        {
            var packets = new List<PacketInfo>();

            using var fs     = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            using var reader = new BinaryReader(fs);

            ValidateAndSkipGlobalHeader(reader);

            while (fs.Position < fs.Length)
            {
                (DateTime timestamp, int savedLength) = ReadPacketHeader(reader);

                byte[] frame = reader.ReadBytes(savedLength);
                if (frame.Length < MinFrameSize) continue;

                PacketInfo? packet = ParseFrame(frame, timestamp);
                if (packet.HasValue)
                    packets.Add(packet.Value);
            }

            return packets;
        }

        // ─── Save Helpers ─────────────────────────────────────────────────────────

        private static void WriteGlobalHeader(BinaryWriter writer)
        {
            writer.Write(PcapMagicNumber);
            writer.Write(PcapMajorVersion);
            writer.Write(PcapMinorVersion);
            writer.Write(0);  // Reserved
            writer.Write(0);  // Reserved
            writer.Write(PcapSnapLen);
            writer.Write(PcapNetworkEthernet);
        }

        private static void WritePacketHeader(BinaryWriter writer, DateTime timestamp, int frameLength)
        {
            long ticks        = timestamp.ToUniversalTime().Ticks - UnixEpoch.Ticks;
            int  seconds      = (int)(ticks / TimeSpan.TicksPerSecond);
            int  microseconds = (int)((ticks % TimeSpan.TicksPerSecond) / 10);

            writer.Write(seconds);
            writer.Write(microseconds);
            writer.Write(frameLength); // Saved length
            writer.Write(frameLength); // Original length
        }

        private static byte[] BuildFrame(PacketInfo p)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            // Ethernet header (14 bytes)
            bw.Write(ParseMacAddress(p.MacDst));
            bw.Write(ParseMacAddress(p.MacSrc));
            bw.Write(new byte[] { 0x08, 0x00 }); // EtherType: IPv4

            // IPv4 header (20 bytes)
            short length = (short)(p.Length > 0 ? p.Length : DefaultLength);
            byte  proto  = p.Protocol.ToUpper().Contains("TCP") ? ProtocolTCP : ProtocolUDP;

            bw.Write((byte)0x45);  // Version=4, IHL=5
            bw.Write((byte)0x00);  // DSCP/ECN
            bw.Write(IPAddress.HostToNetworkOrder(length));
            bw.Write((short)0);    // Identification
            bw.Write((short)0);    // Flags + Fragment Offset
            bw.Write(DefaultTTL);
            bw.Write(proto);
            bw.Write((short)0);    // Checksum (not calculated)
            bw.Write(GetIPv4Bytes(p.SrcIP));
            bw.Write(GetIPv4Bytes(p.DstIP));

            // Transport header — ports (4 bytes)
            bw.Write(IPAddress.HostToNetworkOrder((short)p.SrcPort));
            bw.Write(IPAddress.HostToNetworkOrder((short)p.DstPort));

            // Pad to original packet length if needed
            int padding = p.Length - (int)ms.Length;
            if (padding > 0) bw.Write(new byte[padding]);

            return ms.ToArray();
        }

        // ─── Load Helpers ─────────────────────────────────────────────────────────

        private static void ValidateAndSkipGlobalHeader(BinaryReader reader)
        {
            uint magic = reader.ReadUInt32();
            if (magic != PcapMagicNumber)
                throw new InvalidDataException($"Invalid pcap file. Expected magic 0x{PcapMagicNumber:X8}, got 0x{magic:X8}.");

            reader.ReadInt16();  // Major version
            reader.ReadInt16();  // Minor version
            reader.ReadInt32();  // Reserved
            reader.ReadInt32();  // Reserved
            reader.ReadInt32();  // SnapLen
            reader.ReadInt32();  // Network type
        }

        private static (DateTime timestamp, int savedLength) ReadPacketHeader(BinaryReader reader)
        {
            int seconds      = reader.ReadInt32();
            int microseconds = reader.ReadInt32();
            int savedLength  = reader.ReadInt32();
            reader.ReadInt32(); // Original length (not needed)

            var timestamp = UnixEpoch
                .AddTicks((long)seconds * TimeSpan.TicksPerSecond)
                .AddTicks((long)microseconds * 10);

            return (timestamp, savedLength);
        }

        private static PacketInfo? ParseFrame(byte[] frame, DateTime timestamp)
        {
            try
            {
                int offset = 0;

                // Ethernet header (14 bytes)
                string macDst   = FormatMac(frame, offset); offset += 6;
                string macSrc   = FormatMac(frame, offset); offset += 6;
                ushort etherType = ReadUInt16BigEndian(frame, offset); offset += 2;

                if (etherType != EtherTypeIPv4) return null;

                // IPv4 header (20 bytes)
                offset += 1; // Version + IHL
                offset += 1; // DSCP/ECN

                short totalLength = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(frame, offset)); offset += 2;
                offset += 2; // Identification
                offset += 2; // Flags + Fragment Offset
                offset += 1; // TTL

                byte   protocol     = frame[offset]; offset += 1;
                string protocolName = protocol == ProtocolTCP ? "TCP"
                                    : protocol == ProtocolUDP ? "UDP"
                                    : $"PROTO_{protocol}";

                offset += 2; // Checksum

                string srcIP = ReadIPv4(frame, offset); offset += 4;
                string dstIP = ReadIPv4(frame, offset); offset += 4;

                // Transport ports (4 bytes)
                int srcPort = 0, dstPort = 0;
                if (frame.Length >= offset + 4)
                {
                    srcPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(frame, offset)); offset += 2;
                    dstPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(frame, offset));
                }

                return new PacketInfo
                {
                    Timestamp = timestamp,
                    MacSrc    = macSrc,
                    MacDst    = macDst,
                    SrcIP     = srcIP,
                    DstIP     = dstIP,
                    SrcPort   = srcPort,
                    DstPort   = dstPort,
                    Protocol  = protocolName,
                    Length    = totalLength
                };
            }
            catch
            {
                return null; // Skip malformed packets
            }
        }

        // ─── Utility ──────────────────────────────────────────────────────────────

        /// <summary>Parses a colon-separated MAC string into 6 bytes.</summary>
        private static byte[] ParseMacAddress(string mac)
            => PhysicalAddress.Parse(mac.Replace(":", "-")).GetAddressBytes();

        /// <summary>Formats 6 bytes starting at offset as a colon-separated MAC string.</summary>
        private static string FormatMac(byte[] frame, int offset)
            => string.Join(":", frame.Skip(offset).Take(6).Select(b => b.ToString("X2")));

        /// <summary>Returns the 4 IPv4 bytes of an IP string, or 0.0.0.0 if invalid.</summary>
        private static byte[] GetIPv4Bytes(string ip)
        {
            if (IPAddress.TryParse(ip, out IPAddress addr) &&
                addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                return addr.GetAddressBytes();

            return new byte[] { 0, 0, 0, 0 };
        }

        /// <summary>Reads 4 bytes from frame at offset as an IPv4 address string.</summary>
        private static string ReadIPv4(byte[] frame, int offset)
            => new IPAddress(new[] { frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3] }).ToString();

        /// <summary>Reads a big-endian UInt16 from two bytes.</summary>
        private static ushort ReadUInt16BigEndian(byte[] data, int offset)
            => (ushort)((data[offset] << 8) | data[offset + 1]);
    }
}