using System.Diagnostics;

namespace NetworkScanner
{
    class AnomalyBlocker
    {
        // Blocks a TCP socket (SYN flood, DNS spoofing)
        // Input: ip, port
        public static void Block(string ip, int port)
        {
            if (port > 0)
            {
                // TCP rule with specific port (e.g. SYN flood)
                RunNetsh(
                    $"advfirewall firewall add rule " +
                    $"name=\"Block {ip}:{port}\" " +
                    $"dir=in action=block protocol=TCP localport={port} remoteip={ip}"
                );
            }
            else
            {
                // No port — block all traffic from this IP (ARP spoofing, Evil Twin)
                BlockIp(ip);
            }
        }

        // Blocks all ICMP traffic from a specific IP (ICMP flood)
        public static void BlockIcmp(string ip)
        {
            RunNetsh(
                $"advfirewall firewall add rule " +
                $"name=\"Block ICMP {ip}\" " +
                $"dir=in action=block protocol=ICMP remoteip={ip}"
            );
        }

        // Blocks ALL traffic from a specific IP (ARP spoofing, Evil Twin, catch-all)
        public static void BlockIp(string ip)
        {
            RunNetsh(
                $"advfirewall firewall add rule " +
                $"name=\"Block IP {ip}\" " +
                $"dir=in action=block protocol=any remoteip={ip}"
            );
        }

        // Removes all firewall rules created by our program
        public static void ClearAllBlocks()
        {
            // Delete by name prefix — matches "Block *", "Block ICMP *", "Block IP *"
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