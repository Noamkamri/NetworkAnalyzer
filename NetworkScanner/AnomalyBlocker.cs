using System.Diagnostics;

namespace NetworkScanner
{
    class AnomalyBlocker
    {
        // blocks a specific tcp port from an ip, used for syn flood and dns spoofing
        public static void Block(string ip, int port)
        {
            if (port > 0)
            {
                RunNetsh(
                    $"advfirewall firewall add rule " +
                    $"name=\"Block {ip}:{port}\" " +
                    $"dir=in action=block protocol=TCP localport={port} remoteip={ip}"
                );
            }
            else
            {
                // no port means we want to cut off the ip entirely, e.g. arp spoofing or evil twin
                BlockIp(ip);
            }
        }

        // icmp gets its own rule because it's not tcp/udp so we can't just block a port
        // block all icmp packets from an ip adress
        public static void BlockIcmp(string ip)
        {
            RunNetsh(
                $"advfirewall firewall add rule " +
                $"name=\"Block ICMP {ip}\" " +
                $"dir=in action=block protocol=ICMP remoteip={ip}"
            );
        }

        // blocks everything from this ip, used when we can't narrow it down to a port
        public static void BlockIp(string ip)
        {
            RunNetsh(
                $"advfirewall firewall add rule " +
                $"name=\"Block IP {ip}\" " +
                $"dir=in action=block protocol=any remoteip={ip}"
            );
        }

        // cleans up all the firewall rules we added, called when the user stops sniffing
        public static void ClearAllBlocks()
        {
            // all our rules start with "Block", so deleting by that prefix covers all three types
            foreach (var prefix in new[] { "Block " })
            {
                RunNetsh($"advfirewall firewall delete rule name=\"{prefix}\"");
            }
        }

        private static void RunNetsh(string arguments)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
    }
}