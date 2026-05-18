using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using static NetworkScanner.PacketScanner;

namespace NetworkScanner
{
    public class Statistics
    {
        private const int MAX_SYN_PER_SECOND = Constants.MAX_SYN_PER_SECOND;
        private const int MAX_ICMP_PER_SECOND = Constants.MAX_ICMP_PER_SECOND;

        private ProtocolCount _protocolCount;
        private readonly object _protocolLock = new();

        private readonly Dictionary<string, SocketStats> _sockets = new();
        private readonly HashSet<string> _blockedIps = new();

        // Reference to the Scanner page so we can call RaiseAttack on it
        private Scanner _uiPage;
        public void SetUI(Scanner page) => _uiPage = page;

        private struct SocketStats
        {
            public string Ip { get; set; }
            public string Protocol { get; set; }
            public ushort Port { get; set; }
            public int SYNCount { get; set; }
            public int ICMPCount { get; set; }
        }

        private static string MakeSocketKey(string ip, ushort port) => $"{ip}:{port}";

        public struct ProtocolCount
        {
            public int TCP, UDP, HTTP, HTTPS, ARP, ICMP, DHCP, DNS;
        }

        public void UpdateProtocolCount(in PacketInfo info)
        {
            lock (_protocolLock)
            {
                switch (info.Protocol)
                {
                    case "TCP": _protocolCount.TCP++; break;
                    case "UDP": _protocolCount.UDP++; break;
                    case "HTTP": _protocolCount.HTTP++; break;
                    case "HTTPS": _protocolCount.HTTPS++; break;
                    case "ARP": _protocolCount.ARP++; break;
                    case "ICMP": _protocolCount.ICMP++; break;
                    case "DHCP": _protocolCount.DHCP++; break;
                    case "DNS": _protocolCount.DNS++; break;
                }
            }
        }

        public void UpdateFloodPreventionStats(Packet packet, PacketInfo info)
        {
            lock (_sockets)
            {
                string ip = info.SrcIP;
                ushort port = (ushort)info.SrcPort;
                string key = MakeSocketKey(ip, port);

                var tcp = packet.Extract<TcpPacket>();
                bool isSyn = tcp != null && tcp.Synchronize && !tcp.Acknowledgment;
                bool isIcmp = info.Protocol == "ICMP";

                if (_sockets.TryGetValue(key, out var socket))
                {
                    if (isIcmp) { socket.Protocol = "ICMP"; socket.ICMPCount++; }
                    else if (isSyn) { socket.Protocol = "TCP"; socket.SYNCount++; }
                    _sockets[key] = socket;
                }
                else
                {
                    _sockets[key] = new SocketStats
                    {
                        Ip = ip,
                        Port = port,
                        Protocol = isIcmp ? "ICMP" : (isSyn ? "TCP" : info.Protocol),
                        SYNCount = isSyn ? 1 : 0,
                        ICMPCount = isIcmp ? 1 : 0
                    };
                }
            }
        }

        public void PreventFloodAttacks()
        {
            while (true)
            {
                Thread.Sleep(1000);

                lock (_sockets)
                {
                    foreach (var key in _sockets.Keys.ToArray())
                    {
                        var socket = _sockets[key];

                        if (socket.SYNCount > MAX_SYN_PER_SECOND && !_blockedIps.Contains(socket.Ip))
                        {
                            _blockedIps.Add(socket.Ip);
                            _uiPage?.RaiseAttack(
                                "SYN Flood Detected",
                                $"Source: {socket.Ip}:{socket.Port}",
                                $"{socket.SYNCount} SYN packets/sec from {socket.Ip} on port {socket.Port} — threshold is {MAX_SYN_PER_SECOND}/sec.",
                                socket.Ip, socket.Port
                            );
                            ThreatBlocker.Block(socket.Ip, socket.Port);
                        }

                        if (socket.ICMPCount > MAX_ICMP_PER_SECOND && !_blockedIps.Contains(socket.Ip))
                        {
                            _blockedIps.Add(socket.Ip);
                            _uiPage?.RaiseAttack(
                                "ICMP Flood Detected",
                                $"Source: {socket.Ip}",
                                $"{socket.ICMPCount} ICMP packets/sec from {socket.Ip} — threshold is {MAX_ICMP_PER_SECOND}/sec.",
                                socket.Ip, 0
                            );
                            ThreatBlocker.BlockIcmp(socket.Ip);
                        }

                        socket.SYNCount = 0;
                        socket.ICMPCount = 0;
                        _sockets[key] = socket;
                    }
                }
            }
        }

        public bool IsBlocked(string ip) => _blockedIps.Contains(ip);

        public void ClearBlockedIps() => _blockedIps.Clear();

        public ProtocolCount GetProtocolCountSnapshot()
        {
            lock (_protocolLock)
                return _protocolCount;
        }
    }
}