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
        // lets us find an agent fast by its ip instead of looping through the list every time
        private ConcurrentDictionary<string, ConnectedAgent> _agentMap = new ConcurrentDictionary<string, ConnectedAgent>();
        public ObservableCollection<ConnectedAgent> Agents { get; set; } = new ObservableCollection<ConnectedAgent>();

        // rsa object that holds both the private and public key for the server
        private RSACryptoServiceProvider _rsaServer;

        public MainWindow()
        {
            InitializeComponent(); // builds ui
            AgentsList.ItemsSource = Agents;

            // makes a new 2048 bit key every time the server starts
            _rsaServer = new RSACryptoServiceProvider(2048);

            Task.Run(() => StartListening());
        }

        private async Task StartListening()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, 8888);
            listener.Start();

            while (true) // accepting agents connections infinitly
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                string agentIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString(); //extracts agents ip

                // grab the existing agent for this ip, or make a new one if its the first time we see it
                var agent = _agentMap.GetOrAdd(agentIp, (ip) => {
                    var newAgent = new ConnectedAgent { IP = ip };
                    Dispatcher.Invoke(() => Agents.Add(newAgent));
                    return newAgent;
                });

                _ = HandleAgentMessages(client, agent); // starts handling this specific agent
                                                        // connection without awaiting it here
            }
        }

        private async Task HandleAgentMessages(TcpClient client, ConnectedAgent agent)
        {
            try
            {
                // grab the stream once and wrap it with a reader and writer for text
                using (var stream = client.GetStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                using (var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true })
                {
                    // send the public key to the client first, false means only send the public part
                    string publicKeyXml = _rsaServer.ToXmlString(false);
                    await writer.WriteLineAsync(publicKeyXml);

                    // keep listening for encrypted messages from this agent until it disconnects
                    while (true)
                    {
                        // read the encrypted line, its base64 encoded
                        string encryptedBase64 = await reader.ReadLineAsync();
                        if (encryptedBase64 == null) break; // client disconnected

                        try
                        {
                            // decode from base64 then decrypt with our private key
                            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
                            byte[] decryptedBytes = _rsaServer.Decrypt(encryptedBytes, false);
                            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

                            // now that its plain text we can actually process it
                            ProcessMessage(agent, decryptedMessage);
                        }
                        catch (Exception ex)
                        {
                            // one bad message shouldnt kill the whole connection, just log it and keep going
                            Dispatcher.Invoke(() => agent.AgentAlerts.Insert(0, $"[!] Decryption Error: {ex.Message}"));
                        }
                    }
                }
            }
            catch { } // connection probably dropped, nothing we can do about it
            finally
            {
                // this always runs, whether we broke out cleanly or the connection died
                Dispatcher.Invoke(() => agent.Status = "Disconnected");
                client.Close();
            }
        }

        private void ProcessMessage(ConnectedAgent agent, string message)
        {
            // messages look like this, type|value or type|value|extra
            var parts = message.Split('|');
            if (parts.Length < 2) return; // not a valid message, ignore it

            string type = parts[0];
            string value = parts[1];

            // we are on a background thread here, but this touches ui stuff, so it has to run through dispatcher
            Dispatcher.Invoke(() =>
            {
                switch (type)
                {
                    case "ALERT":
                        if (parts.Length >= 3)
                        {
                            // newest alert goes on top of the list
                            agent.AgentAlerts.Insert(0, $"[{DateTime.Now:HH:mm}] {value}: {parts[2]}");
                            agent.Status = "ANOMALY DETECTED!";
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
                        // format looks like this, TCP:10,UDP:5,HTTP:2...
                        var protocolData = value.Split(',');
                        foreach (var p in protocolData)
                        {
                            var kv = p.Split(':');
                            if (kv.Length == 2)
                            {
                                string protoName = kv[0];
                                if (int.TryParse(kv[1], out int pCount))
                                {
                                    // update it if we already have this protocol for this agent, otherwise add it
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