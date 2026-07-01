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

        // tracks which mac first responded to each dns transaction id, so we can spot a second mac answering the same query
        private ConcurrentDictionary<ushort, string> dnsMacTracker = new();
        private DateTime _lastDnsAlertTime = DateTime.MinValue;
        // cooldown lock so we don't spam alerts if a spoofed dns server is very chatty
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

            // promiscuous mode means we capture all traffic on the network, not just packets addressed to us
            device.Open(DeviceModes.Promiscuous, 10);

            StartProcessingThread();

            Thread floodPreventionThread =
                new Thread(() => stats.PreventFloodAnomalies())
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
                    // GetConsumingEnumerable blocks automatically when the queue is empty, no need to spin or sleep
                    foreach (var raw in PacketQueue.Queue.GetConsumingEnumerable()) // never ending loop, GetConsumingEnumerable() waits when the queue is empty instead of exiting
                    {
                        try
                        {
                            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data); 
                            var info = BuildPacketInfo(packet, raw);

                            // drop packets from ips we already blocked so they don't show up in the ui
                            if (stats.IsBlocked(info.SrcIP)) continue;

                            stats.UpdateFloodPreventionStats(packet, info);
                            stats.UpdateProtocolCount(in info);
                            HandleArp(packet);

                            // only push to ui if the protocol is one we actually support
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

            // TryAdd is non blocking, if the queue is full we just drop the packet rather than slowing the capture thread
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

            var ip = packet.Extract<IPPacket>(); // both src & dest
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

                // dns responses come from port 53, first 2 bytes of the payload are the transaction id
                if (protocol == "DNS" && srcPort == 53 && udp.PayloadData.Length >= 2)
                {
                    ushort transactionID = (ushort)((udp.PayloadData[0] << 8) | udp.PayloadData[1]);
                    HandleDns(transactionID, srcIP, srcMac);
                }
            }

            if (!allowedProtocols.Contains(protocol))
                protocol = "UNSUPPORTED";

            // SharpPcap timestamps can be unspecified kind, we normalize to local time so the ui shows the right time
            var ts = raw.Timeval.Date;
            if (ts.Kind == DateTimeKind.Unspecified) // convert time to UTC
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

            // tls handshake always starts with 0x16 0x03, that's the reliable way to detect https regardless of port
            if (payload.Length >= 3 && payload[0] == 0x16 && payload[1] == 0x03)
                return "HTTPS";

            // check if the payload starts with an http method keyword
            if (payload.Length >= 4)
            {
                string startStr = System.Text.Encoding.ASCII.GetString(payload, 0, 4).ToUpper();
                if (startStr.StartsWith("GET") || startStr.StartsWith("POST") ||
                    startStr.StartsWith("HEAD") || startStr.StartsWith("HTTP"))
                    return "HTTP";
            }

            // no byte signature matched, fall back to well-known port numbers
            // we prefer the lower port since that's more likely to be the service side
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
                device.StopCapture(); // stop sniffing
                device.Close();
                stats?.ClearBlockedIps(); // clear block ips
                AnomalyBlocker.ClearAllBlocks(); // clear firewall rules
            }
        }

        public Statistics.ProtocolCount GetProtocolCountSnapshot() => stats != null ? stats.GetProtocolCountSnapshot() : new Statistics.ProtocolCount();

        void HandleArp(Packet packet)
        {
            var eth = packet as EthernetPacket;
            if (eth == null) return;

            var arp = eth.PayloadPacket as ArpPacket;
            if (arp == null) return;

            string ip = arp.SenderProtocolAddress.ToString();
            string mac = arp.SenderHardwareAddress.ToString();

            // GetOrAdd returns the existing value if the key is already there, so if the mac we get back
            // is different from the one in this packet, someone is claiming an ip that belongs to another mac
            string existingMac = arpTable.GetOrAdd(ip, mac);
            if (existingMac != mac)
                RaiseAnomaly("ARP Spoofing", ip, $"MAC changed from {existingMac} to {mac}", ip, 0);
        }

        void HandleDns(ushort txId, string sourceIp, string sourceMac)
        {
            if (dnsMacTracker.TryGetValue(txId, out string firstMac))
            {
                // same transaction id answered by a different mac, that's dns spoofing
                if (firstMac != sourceMac)
                {
                    lock (_dnsAlertLock)
                    {
                        // 4 second cooldown so we don't flood the alert overlay if it keeps happening
                        if ((DateTime.Now - _lastDnsAlertTime).TotalSeconds > 4)
                        {
                            _lastDnsAlertTime = DateTime.Now;
                            RaiseAnomaly("DNS Spoofing", sourceIp,
                                $"MAC conflict on transaction ID {txId:X4} — expected {firstMac}, got {sourceMac}.",
                                sourceIp, 53);
                        }
                    }
                    dnsMacTracker.TryRemove(txId, out _);
                }
            }
            else
            {
                // first time we see this transaction id, record which mac answered it
                dnsMacTracker.TryAdd(txId, sourceMac);
                // clean up after 5 seconds so we don't leak memory if the query never gets a second reply
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    dnsMacTracker.TryRemove(txId, out _);
                });
            }
        }

        // All anomaly types funnel through here → Scanner overlay
        private void RaiseAnomaly(string type, string target, string details, string ip = "", int port = 0)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                uiPage?.RaiseAnomaly(type, target, details, ip, port);
            });
        }
    }
}