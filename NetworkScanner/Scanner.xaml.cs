using SharpPcap;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using System.Security.Cryptography;
using System.IO;
using System.Threading.Tasks;

namespace NetworkScanner
{
    public partial class Scanner : Page
    {
        private PacketScanner scanner;

        private ScrollViewer _packetsScrollViewer;
        private bool _followPackets = true;
        private int _ignoreScrollEvents = 0;
        private bool _isSniffing = true;

        private const int MaxDisplayedPackets = 20000;
        private static readonly TimeSpan UIFlushInterval = TimeSpan.FromMilliseconds(50);

        private readonly ConcurrentQueue<PacketScanner.PacketInfo> _pendingPackets = new();
        private DispatcherTimer _uiFlushTimer;
        private DispatcherTimer _statsSyncTimer;

        private int _totalScannedPackets = 0;

        private ICaptureDevice _currentDevice;

        // --- Class Members for Evil Twin Defense ---
        private DispatcherTimer _securityTimer;
        private string _baselineBssid = "";
        private string _baselineSsid = "";

        // Last attacker info
        private string _alertIp = "";
        private int _alertPort = 0;
        private string _alertType = "";

        /// Central server communication
        private TcpClient _serverClient;
        private StreamWriter _serverWriter;
        private RSACryptoServiceProvider _rsaClient;

        private bool hasPreviousData = false;
        public ObservableCollection<PacketScanner.PacketInfo> Packets { get; }
            = new ObservableCollection<PacketScanner.PacketInfo>();

        public ProtocolBarsVM ProtocolVM { get; private set; }

        public Scanner(ICaptureDevice device)
        {
            InitializeComponent();

            PacketsGrid.ItemsSource = Packets;

            _currentDevice = device;

            scanner = new PacketScanner();
            scanner.SetUI(this);
            scanner.Start(device);

            StartEvilTwinDefense();

            _uiFlushTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = UIFlushInterval
            };
            _uiFlushTimer.Tick += FlushPendingPackets;
            _uiFlushTimer.Start();

            ProtocolVM = new ProtocolBarsVM(scanner.GetProtocolCountSnapshot);
            DataContext = this;

            Loaded += Scanner_Loaded;
            Unloaded += Scanner_Unloaded;

            // Connect to the central management server
            ConnectToCentralServer("127.0.0.1", 8888);

            // Timer for Protocol Stats
            _statsSyncTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(1)
            };

            _statsSyncTimer.Tick += (s, e) =>
            {
                if (!_isSniffing) return;
                var counts = scanner.GetProtocolCountSnapshot();
                string statsMsg = $"PROTOCOL_STATS|TCP:{counts.TCP},UDP:{counts.UDP},HTTP:{counts.HTTP},HTTPS:{counts.HTTPS},ARP:{counts.ARP},ICMP:{counts.ICMP},DHCP:{counts.DHCP},DNS:{counts.DNS}";
                Task.Run(() => SendMessageToServer(statsMsg));
            };
            _statsSyncTimer.Start();
        }

        public Scanner(List<PacketScanner.PacketInfo> packets)
        {
            InitializeComponent();

            PacketsGrid.ItemsSource = Packets;

            foreach (var packet in packets)
                Packets.Add(packet);

            StopButton.IsEnabled = false;
            StopButton.Content = "Stopped";
            StopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1E2535"));

            SavePcapButton.IsEnabled = true;

            ProtocolVM = new ProtocolBarsVM(() => new Statistics.ProtocolCount());
            DataContext = this;

            Loaded += Scanner_Loaded;
            Unloaded += Scanner_Unloaded;
        }

        // ─────────────────────────────────────────────────
        // EVIL TWIN DETECTION
        // ─────────────────────────────────────────────────

        private string GetNetshValue(string key)
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    foreach (string line in output.Split(new[] { Environment.NewLine }, StringSplitOptions.None))
                    {
                        if (line.Contains(key) && (key != "SSID" || !line.Contains("BSSID")))
                        {
                            int colonIndex = line.IndexOf(':');
                            if (colonIndex != -1)
                                return line.Substring(colonIndex + 1).Trim();
                        }
                    }
                }
            }
            catch { }
            return "";
        }

        private string GetCurrentBssid() => GetNetshValue("BSSID").ToUpper();
        private string GetCurrentSsid() => GetNetshValue("SSID");

        private void StartEvilTwinDefense()
        {
            _baselineBssid = GetCurrentBssid();
            _baselineSsid = GetCurrentSsid();

            if (string.IsNullOrEmpty(_baselineBssid)) return;

            _securityTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _securityTimer.Tick += (s, e) =>
            {
                string currentMac = GetCurrentBssid();
                string currentSsid = GetCurrentSsid();

                if (string.IsNullOrEmpty(currentMac)) return;

                if (currentSsid == _baselineSsid && currentMac != _baselineBssid)
                {
                    RaiseAttack("Evil Twin Detected", "Wi-Fi Integrity",
                        $"You are still on '{currentSsid}', but the hardware identity changed from {_baselineBssid} to {currentMac}!");
                }
            };
            _securityTimer.Start();
        }

        // ─────────────────────────────────────────────────
        // INLINE SECURITY ALERT
        // ─────────────────────────────────────────────────

        public void RaiseAttack(string type, string target, string details, string ip = "", int port = 0)
        {
            // Fire and forget the network transmission
            Task.Run(() => SendMessageToServer($"ALERT|{type}|{target} - {details}"));

            Dispatcher.Invoke(() =>
            {
                this.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F1D1D"));

                _alertIp = ip;
                _alertPort = port;
                _alertType = type;

                AlertTypeLabel.Text = type;
                AlertTargetLabel.Text = target;
                AlertDetailsLabel.Text = details;
                AlertTimeLabel.Text = DateTime.Now.ToString("HH:mm:ss   dd MMM yyyy");

                AlertOverlay.Visibility = Visibility.Visible;
            });
        }

        public void ConnectToCentralServer(string serverIp, int port)
        {
            Task.Run(async () =>
            {
                try
                {
                    _serverClient = new TcpClient(serverIp, port);
                    NetworkStream stream = _serverClient.GetStream();

                    StreamReader reader = new StreamReader(stream, Encoding.UTF8);
                    _serverWriter = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

                    _rsaClient = new RSACryptoServiceProvider(2048);

                    // 1. Receive Public Key from Server
                    string publicKeyXml = await reader.ReadLineAsync();

                    if (!string.IsNullOrEmpty(publicKeyXml))
                    {
                        // Load the server's lock into our RSA client
                        _rsaClient.FromXmlString(publicKeyXml);

                        // 2. Send an initial encrypted "Hello"
                        SendMessageToServer("HEARTBEAT|0");
                    }
                }
                catch { /* Server is offline */ }
            });
        }

        private void SendMessageToServer(string message)
        {
            try
            {
                if (_serverWriter != null && _serverClient.Connected && _rsaClient != null)
                {
                    // 1. Convert to bytes
                    byte[] dataToEncrypt = Encoding.UTF8.GetBytes(message);

                    // 2. Encrypt
                    byte[] encryptedData = _rsaClient.Encrypt(dataToEncrypt, false);

                    // 3. Convert to Base64
                    string base64Encrypted = Convert.ToBase64String(encryptedData);

                    // 4. Send
                    _serverWriter.WriteLine(base64Encrypted);
                }
            }
            catch { /* Handle disconnection */ }
        }

        private void AlertClose_Click(object sender, RoutedEventArgs e)
        {
            AlertOverlay.Visibility = Visibility.Collapsed;
            this.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0D0F12"));
        }

        private void AlertBlock_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_alertIp))
            {
                if (_alertType.Contains("ICMP"))
                    ThreatBlocker.BlockIcmp(_alertIp);
                else if (_alertType.Contains("ARP") || _alertType.Contains("Evil Twin"))
                    ThreatBlocker.BlockIp(_alertIp);
                else
                    ThreatBlocker.Block(_alertIp, _alertPort);
            }

            AlertOverlay.Visibility = Visibility.Collapsed;
            this.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0D0F12"));
        }

        // ─────────────────────────────────────────────────
        // EXISTING FEATURES (PCAP, UI, Scrolling)
        // ─────────────────────────────────────────────────

        public void AddPacket(PacketScanner.PacketInfo packet)
        {
            _pendingPackets.Enqueue(packet);
        }

        private void FlushPendingPackets(object sender, EventArgs e)
        {
            const int maxPerFlush = 500;
            int count = 0;
            while (count < maxPerFlush && _pendingPackets.TryDequeue(out var packet))
            {
                Packets.Add(packet);
                count++;
                _totalScannedPackets++;
            }
            int excess = Packets.Count - MaxDisplayedPackets;
            for (int i = 0; i < excess; i++) Packets.RemoveAt(0);
            if (count > 0 && _followPackets) ForceScrollToBottom();

            if (count > 0)
            {
                Task.Run(() => SendMessageToServer($"STATS|{_totalScannedPackets}"));
            }
        }

        private void Scanner_Loaded(object sender, RoutedEventArgs e)
        {
            _packetsScrollViewer ??= FindVisualChild<ScrollViewer>(PacketsGrid);
            if (_packetsScrollViewer != null) _packetsScrollViewer.ScrollChanged += PacketsScrollViewer_ScrollChanged;
            _followPackets = true;
            ForceScrollToBottom();
        }

        private void Scanner_Unloaded(object sender, RoutedEventArgs e)
        {
            if (_packetsScrollViewer != null) _packetsScrollViewer.ScrollChanged -= PacketsScrollViewer_ScrollChanged;
            if (ProtocolVM != null) ProtocolVM.IsMonitoring = false;
            _uiFlushTimer?.Stop();
            _securityTimer?.Stop();
            _statsSyncTimer?.Stop();
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isSniffing)
            {
                // עוצר את ההסנפה במחלקת ה-PacketScanner
                // (אם הפונקציה שלך נקראת בשם אחר כמו StopCapture, שנה בהתאם)
                scanner.Stop();

                _isSniffing = false;
                hasPreviousData = true;

                StopButton.Content = "Start Sniffing";
                StopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981")); // צבע ירוק

                // מדליק את האפשרות לשמור קובץ
                SavePcapButton.IsEnabled = true;
            }
            else
            {
                if (hasPreviousData)
                {
                    // מעלים את הכפתור הראשי ומציג את שתי האפשרויות
                    StopButton.Visibility = Visibility.Collapsed;
                    spResumeOptions.Visibility = Visibility.Visible;
                }
                else
                {
                    // מפעיל מחדש אם איכשהו הגענו לפה בלי נתונים
                    scanner.Start(_currentDevice);
                    _isSniffing = true;
                    StopButton.Content = "Stop Sniffing";
                    StopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC2626")); // חזרה לאדום
                    SavePcapButton.IsEnabled = false;
                }
            }
        }

        private void BtnContinue_Click(object sender, RoutedEventArgs e)
        {
            // מחזיר את התצוגה של הכפתור הראשי
            spResumeOptions.Visibility = Visibility.Collapsed;
            StopButton.Visibility = Visibility.Visible;

            StopButton.Content = "Stop Sniffing";
            StopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC2626"));

            _isSniffing = true;
            SavePcapButton.IsEnabled = false;

            // ממשיך את ההסנפה בלי למחוק כלום מהמסך
            scanner.Start(_currentDevice);
        }

        private void BtnNewSession_Click(object sender, RoutedEventArgs e)
        {
            // מחזיר את התצוגה של הכפתור הראשי
            spResumeOptions.Visibility = Visibility.Collapsed;
            StopButton.Visibility = Visibility.Visible;

            StopButton.Content = "Stop Sniffing";
            StopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC2626"));

            _isSniffing = true;
            SavePcapButton.IsEnabled = false;

            // מאפס את כל הנתונים במסך ומוחק סטטיסטיקות
            Packets.Clear();
            _totalScannedPackets = 0;
            // *אם יש לך פונקציה ב-scanner שמאפסת סטטיסטיקות, קרא לה פה*

            // מתחיל הסנפה נקייה לגמרי
            scanner.Start(_currentDevice);
        }

        private void SavePcapButton_Click(object sender, RoutedEventArgs e)
        {
            var packetsToSave = new List<PacketScanner.PacketInfo>();
            foreach (var item in PacketsGrid.Items)
            {
                if (item is PacketScanner.PacketInfo info) packetsToSave.Add(info);
            }
            if (packetsToSave.Count == 0) return;
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string fileName = $"Capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap";
            string fullPath = System.IO.Path.Combine(desktopPath, fileName);
            try
            {
                PcapHandler.SaveToPcap(fullPath, packetsToSave);
                MessageBox.Show($"Saved to: {fullPath}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        private void PacketsScrollViewer_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (_packetsScrollViewer == null) return;
            bool atBottom = _packetsScrollViewer.ScrollableHeight <= 0 || _packetsScrollViewer.VerticalOffset >= _packetsScrollViewer.ScrollableHeight - 12;
            ScrollToBottomButton.Visibility = atBottom ? Visibility.Collapsed : Visibility.Visible;
            if (e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0 && e.VerticalChange != 0) _followPackets = false;
            if (atBottom && userScroll_check(e)) _followPackets = true;
        }
        private bool userScroll_check(ScrollChangedEventArgs e) => e.ExtentHeightChange != 0 || e.VerticalChange != 0;

        private void ScrollToBottomButton_Click(object sender, RoutedEventArgs e) { _followPackets = true; ForceScrollToBottom(); }
        private void ForceScrollToBottom() { _ignoreScrollEvents = 6; _packetsScrollViewer?.ScrollToEnd(); }

        private static T FindVisualChild<T>(DependencyObject obj) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(obj); i++)
            {
                var child = VisualTreeHelper.GetChild(obj, i);
                if (child is T t) return t;
                var childOfChild = FindVisualChild<T>(child);
                if (childOfChild != null) return childOfChild;
            }
            return null;
        }

        private void CheckFilter(object sender, RoutedEventArgs e)
        {
            string filterText = FilterTextBox.Text.Trim().ToLower();
            PacketsGrid.Items.Filter = item => {
                if (item is PacketScanner.PacketInfo p) return string.IsNullOrEmpty(filterText) || p.Protocol.ToLower().Contains(filterText) || p.SrcIP.Contains(filterText) || p.DstIP.Contains(filterText);
                return false;
            };
        }
    }
}