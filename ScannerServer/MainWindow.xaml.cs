using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Security.Cryptography;
using System.IO;

namespace ScannerServer
{
    public partial class MainWindow : Window
    {
        // Thread-safe dictionary to quickly find agents by their IP
        private ConcurrentDictionary<string, ConnectedAgent> _agentMap = new ConcurrentDictionary<string, ConnectedAgent>();
        public ObservableCollection<ConnectedAgent> Agents { get; set; } = new ObservableCollection<ConnectedAgent>();

        // אובייקט ה-RSA של השרת שמחזיק את המפתח הפרטי והפומבי
        private RSACryptoServiceProvider _rsaServer;

        public MainWindow()
        {
            InitializeComponent();
            AgentsList.ItemsSource = Agents;

            // ייצור מפתח 2048 ביט חדש כשהשרת עולה
            _rsaServer = new RSACryptoServiceProvider(2048);

            Task.Run(() => StartListening());
        }

        private async Task StartListening()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, 8888);
            listener.Start();

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                string agentIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

                // Get existing agent or create a new one
                var agent = _agentMap.GetOrAdd(agentIp, (ip) => {
                    var newAgent = new ConnectedAgent { IP = ip };
                    Dispatcher.Invoke(() => Agents.Add(newAgent));
                    return newAgent;
                });

                _ = HandleAgentMessages(client, agent);
            }
        }

        private async Task HandleAgentMessages(TcpClient client, ConnectedAgent agent)
        {
            try
            {
                using (var stream = client.GetStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                using (var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true })
                {
                    // 1. שליחת המפתח הפומבי ללקוח (false = רק מפתח פומבי)
                    string publicKeyXml = _rsaServer.ToXmlString(false);
                    await writer.WriteLineAsync(publicKeyXml);

                    // 2. לולאת האזנה להודעות מוצפנות מהלקוח
                    while (true)
                    {
                        // קריאת ההודעה המוצפנת (פורמט Base64)
                        string encryptedBase64 = await reader.ReadLineAsync();
                        if (encryptedBase64 == null) break; // הלקוח התנתק

                        try
                        {
                            // 3. פענוח ההודעה
                            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
                            byte[] decryptedBytes = _rsaServer.Decrypt(encryptedBytes, false);
                            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

                            // 4. עיבוד ההודעה הגלויה
                            ProcessMessage(agent, decryptedMessage);
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() => agent.AgentAlerts.Insert(0, $"[!] Decryption Error: {ex.Message}"));
                        }
                    }
                }
            }
            catch { }
            finally
            {
                Dispatcher.Invoke(() => agent.Status = "Disconnected");
                client.Close();
            }
        }

        private void ProcessMessage(ConnectedAgent agent, string message)
        {
            var parts = message.Split('|');
            if (parts.Length < 2) return;

            string type = parts[0];
            string value = parts[1];

            Dispatcher.Invoke(() =>
            {
                switch (type)
                {
                    case "ALERT":
                        if (parts.Length >= 3)
                        {
                            agent.AgentAlerts.Insert(0, $"[{DateTime.Now:HH:mm}] {value}: {parts[2]}");
                            agent.Status = "ANOMALY DETECTED!"; // שינינו מ-Attack ל-Anomaly לקראת התיק
                        }
                        break;

                    case "STATS":
                        if (int.TryParse(value, out int count))
                            agent.TotalPackets = count;
                        break;

                    case "HEARTBEAT":
                        agent.Status = "Online / Scanning";
                        break;

                    case "PROTOCOL_STATS":
                        // Format: PROTOCOL_STATS|TCP:10,UDP:5,HTTP:2...
                        var protocolData = value.Split(',');
                        foreach (var p in protocolData)
                        {
                            var kv = p.Split(':');
                            if (kv.Length == 2)
                            {
                                string protoName = kv[0];
                                if (int.TryParse(kv[1], out int pCount))
                                {
                                    var existing = agent.Protocols.FirstOrDefault(x => x.Name == protoName);
                                    if (existing != null)
                                        existing.Count = pCount;
                                    else
                                        agent.Protocols.Add(new ProtocolStat { Name = protoName, Count = pCount });
                                }
                            }
                        }
                        break;
                }
            });
        }
    }
}