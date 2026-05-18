using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;
using System.Windows;
using System.Net.Sockets;

namespace NetworkScanner
{
    public class PacketScanner
    {
        public struct PacketInfo
        {
            public DateTime Timestamp { get; set; }
            public string SrcIP { get; set; }
            public string DstIP { get; set; }
            public int Length { get; set; }
            public string Protocol { get; set; }
            public int SrcPort { get; set; }
            public int DstPort { get; set; }
            public string MacSrc { get; set; }
            public string MacDst { get; set; }

            public string SrcEndpoint => $"{SrcIP}:{SrcPort}";
            public string DstEndpoint => $"{DstIP}:{DstPort}";
        }

        private ICaptureDevice device;
        private Scanner uiPage;
        private string[] allowedProtocols = Array.Empty<string>();
        private Statistics stats;
        ConcurrentDictionary<string, string> arpTable = new();

        // --- DNS Spoofing Variables ---
        private ConcurrentDictionary<ushort, string> dnsMacTracker = new();
        private DateTime _lastDnsAlertTime = DateTime.MinValue;
        private readonly object _dnsAlertLock = new object();

        public void SetUI(Scanner page)
        {
            uiPage = page;
        }

        public void Start(ICaptureDevice dev)
        {
            allowedProtocols = new[] { "TCP", "UDP", "ICMP", "ARP", "DNS", "DHCP", "HTTP", "HTTPS" };
            device = dev;
            stats = new Statistics();

            // Wire the Scanner page into Statistics so flood alerts use the overlay
            stats.SetUI(uiPage);

            device.Open(DeviceModes.Promiscuous, 10);

            StartProcessingThread();

            Thread floodPreventionThread =
                new Thread(() => stats.PreventFloodAttacks())
                {
                    IsBackground = true
                };
            floodPreventionThread.Start();

            device.OnPacketArrival += OnPacketArrival;
            device.StartCapture();
        }

        private const int WorkerCount = 4;

        private void StartProcessingThread()
        {
            for (int i = 0; i < WorkerCount; i++)
            {
                Task.Run(() =>
                {
                    foreach (var raw in PacketQueue.Queue.GetConsumingEnumerable())
                    {
                        try
                        {
                            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
                            var info = BuildPacketInfo(packet, raw);

                            // If this IP has been blocked, drop it silently
                            if (stats.IsBlocked(info.SrcIP)) continue;

                            stats.UpdateFloodPreventionStats(packet, info);
                            stats.UpdateProtocolCount(in info);
                            HandleArp(packet);

                            if (info.Protocol != "UNSUPPORTED")
                            {
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    uiPage?.AddPacket(info);
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Error processing packet: " + ex.Message);
                        }
                    }
                });
            }
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            var raw = e.GetPacket();
            if (!PacketQueue.Queue.TryAdd(raw))
                Console.WriteLine("Queue full — packet dropped.");
        }

        private PacketInfo BuildPacketInfo(Packet packet, RawCapture raw)
        {
            string srcIP = "";
            string dstIP = "";
            string srcMac = "";
            string dstMac = "";
            int srcPort = 0;
            int dstPort = 0;
            string protocol = "";

            var ip = packet.Extract<IPPacket>();
            if (ip != null)
            {
                srcIP = ip.SourceAddress.ToString();
                dstIP = ip.DestinationAddress.ToString();
            }

            var eth = packet.Extract<EthernetPacket>();
            if (eth != null)
            {
                srcMac = eth.SourceHardwareAddress.ToString();
                dstMac = eth.DestinationHardwareAddress.ToString();
            }

            var arp = packet.Extract<ArpPacket>();
            if (arp != null) protocol = "ARP";

            if (packet.Extract<IcmpV4Packet>() != null ||
                packet.Extract<IcmpV6Packet>() != null)
                protocol = "ICMP";

            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null)
            {
                srcPort = tcp.SourcePort;
                dstPort = tcp.DestinationPort;
                protocol = DetectProtocol(tcp.PayloadData, srcPort, dstPort, "TCP");
            }

            var udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                srcPort = udp.SourcePort;
                dstPort = udp.DestinationPort;
                protocol = DetectProtocol(udp.PayloadData, srcPort, dstPort, "UDP");

                if (protocol == "DNS" && srcPort == 53 && udp.PayloadData.Length >= 2)
                {
                    ushort transactionID = (ushort)((udp.PayloadData[0] << 8) | udp.PayloadData[1]);
                    HandleDns(transactionID, srcIP, srcMac);
                }
            }

            if (!allowedProtocols.Contains(protocol))
                protocol = "UNSUPPORTED";

            var ts = raw.Timeval.Date;
            if (ts.Kind == DateTimeKind.Unspecified)
                ts = DateTime.SpecifyKind(ts, DateTimeKind.Utc).ToLocalTime();
            else
                ts = ts.ToLocalTime();

            return new PacketInfo
            {
                Timestamp = ts,
                SrcIP = srcIP,
                DstIP = dstIP,
                Length = raw.Data.Length,
                Protocol = protocol,
                SrcPort = srcPort,
                DstPort = dstPort,
                MacSrc = srcMac,
                MacDst = dstMac
            };
        }

        private string DetectProtocol(byte[] payload, int srcPort, int dstPort, string defaultProtocol)
        {
            if (payload == null || payload.Length == 0)
                return "TCP";

            if (payload.Length >= 3 && payload[0] == 0x16 && payload[1] == 0x03)
                return "HTTPS";

            if (payload.Length >= 4)
            {
                string startStr = System.Text.Encoding.ASCII.GetString(payload, 0, 4).ToUpper();
                if (startStr.StartsWith("GET") || startStr.StartsWith("POST") ||
                    startStr.StartsWith("HEAD") || startStr.StartsWith("HTTP"))
                    return "HTTP";
            }

            int port = (srcPort <= 1023) ? srcPort : dstPort;
            return port switch
            {
                53 => "DNS",
                67 or 68 => "DHCP",
                80 => "HTTP (Port)",
                443 => "Unknown (443)",
                _ => defaultProtocol
            };
        }

        public void Stop()
        {
            if (device != null && device.Started)
            {
                device.StopCapture();
                device.Close();
                stats?.ClearBlockedIps();
                ThreatBlocker.ClearAllBlocks();
            }
        }

        public Statistics.ProtocolCount GetProtocolCountSnapshot()
            => stats != null ? stats.GetProtocolCountSnapshot() : new Statistics.ProtocolCount();

        void HandleArp(Packet packet)
        {
            var eth = packet as EthernetPacket;
            if (eth == null) return;

            var arp = eth.PayloadPacket as ArpPacket;
            if (arp == null) return;

            string ip = arp.SenderProtocolAddress.ToString();
            string mac = arp.SenderHardwareAddress.ToString();

            string existingMac = arpTable.GetOrAdd(ip, mac);
            if (existingMac != mac)
                RaiseAttack("ARP Spoofing", ip, $"MAC changed from {existingMac} to {mac}", ip, 0);
        }

        void HandleDns(ushort txId, string sourceIp, string sourceMac)
        {
            if (dnsMacTracker.TryGetValue(txId, out string firstMac))
            {
                if (firstMac != sourceMac)
                {
                    lock (_dnsAlertLock)
                    {
                        if ((DateTime.Now - _lastDnsAlertTime).TotalSeconds > 4)
                        {
                            _lastDnsAlertTime = DateTime.Now;
                            RaiseAttack("DNS Spoofing", sourceIp,
                                $"MAC conflict on transaction ID {txId:X4} — expected {firstMac}, got {sourceMac}.",
                                sourceIp, 53);
                        }
                    }
                    dnsMacTracker.TryRemove(txId, out _);
                }
            }
            else
            {
                dnsMacTracker.TryAdd(txId, sourceMac);
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    dnsMacTracker.TryRemove(txId, out _);
                });
            }
        }

        // All attack types funnel through here → Scanner overlay
        private void RaiseAttack(string type, string target, string details, string ip = "", int port = 0)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                uiPage?.RaiseAttack(type, target, details, ip, port);
            });
        }
    }
}