using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;
using System.IO;

namespace NetworkScanner
{
    public partial class ChooseDevice : Page
    {
        private ICaptureDevice? _selectedCaptureDevice;
        private DispatcherTimer _interfaceRefreshTimer;

        public class CaptureInterfaceItem
        {
            public ICaptureDevice? CaptureDevice { get; set; }
            public string InterfaceType { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string IconPath { get; set; } = string.Empty;
        }

        public ChooseDevice()
        {
            InitializeComponent();

            LoadCaptureInterfaces();

            DeviceList.SelectionChanged += OnDeviceSelectionChanged;

            // re-scan for interfaces every 5 seconds in case the user plugs something in after opening the app
            _interfaceRefreshTimer = new DispatcherTimer();
            _interfaceRefreshTimer.Interval = TimeSpan.FromSeconds(5);

            _interfaceRefreshTimer.Tick += RefreshInterfaces;
            _interfaceRefreshTimer.Start();
        }

        private void LoadCaptureInterfaces()
        {
            // remember what was selected before the refresh so we can restore it after rebuilding the list
            ICaptureDevice? previouslySelectedDevice = null;

            if (DeviceList.SelectedItem is CaptureInterfaceItem selectedItem)
            {
                previouslySelectedDevice = selectedItem.CaptureDevice;
            }

            var captureDevices = CaptureDeviceList.New();
            var interfaceItems = new List<CaptureInterfaceItem>();

            foreach (var captureDevice in captureDevices)
            {
                string description = captureDevice.Description ?? string.Empty;
                string deviceName = captureDevice.Name ?? string.Empty;

                // skip virtual and internal windows adapters that aren't real capture interfaces
                if (description.Contains("Miniport") ||
                    description.Contains("Monitor") ||
                    description.Contains("Virtual") ||
                    description.Contains("Filter") ||
                    description.Contains("QoS") ||
                    description.Contains("Bluetooth"))
                {
                    continue;
                }

                // default to ethernet, then check description and name keywords to detect wifi or loopback
                string iconPath = "Icons/Ethernet.png";
                string interfaceType = "Ethernet";

                if (description.Contains("wireless", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("wifi", StringComparison.OrdinalIgnoreCase) ||
                    deviceName.Contains("wifi", StringComparison.OrdinalIgnoreCase) ||
                    deviceName.Contains("wi-fi", StringComparison.OrdinalIgnoreCase))
                {
                    iconPath = "Icons/Wifi.png";
                    interfaceType = "Wi-Fi";
                }
                else if (description.Contains("loopback", StringComparison.OrdinalIgnoreCase))
                {
                    iconPath = "Icons/Loopback.png";
                    interfaceType = "Loopback";
                }

                interfaceItems.Add(new CaptureInterfaceItem
                {
                    CaptureDevice = captureDevice,
                    InterfaceType = interfaceType,
                    Description = description,
                    IconPath = iconPath
                });
            }
            
            DeviceList.ItemsSource = interfaceItems; // shows thelist of devices

            // restore the previous selection by matching on device name after the list rebuilds
            if (previouslySelectedDevice != null)
            {
                CaptureInterfaceItem? matchedItem = null;

                foreach (var item in interfaceItems)
                {
                    if (item.CaptureDevice != null && item.CaptureDevice.Name == previouslySelectedDevice.Name)
                    {
                        matchedItem = item;
                        break;
                    }
                }

                DeviceList.SelectedItem = matchedItem;
            }
        }

        private void StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (DeviceList.SelectedItem is not CaptureInterfaceItem selectedInterface ||
                selectedInterface.CaptureDevice == null)
            {
                MessageBox.Show("Please select a valid capture interface.");
                return;
            }

            _selectedCaptureDevice = selectedInterface.CaptureDevice;
            NavigationService.Navigate(new Scanner(_selectedCaptureDevice));
        }

        private void RefreshInterfaces(object? sender, EventArgs e)
        {
            // kick off the spin animation on the refresh icon so the user can see it's scanning
            if (FindResource("RefreshSpinStoryboard") is Storyboard storyboard)
            {
                storyboard.Begin();
            }

            LoadCaptureInterfaces();
        }

        private void OnDeviceSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            StartScanButton.IsEnabled = DeviceList.SelectedItem != null;
        }

        private void OpenPcap_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog // windows choose a file pop up
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), //opens directory folder
                Filter = "PCAP files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*", // some filters
                RestoreDirectory = true
            };

            if (openFileDialog.ShowDialog() == true)
            {
                var packets = PcapHandler.LoadFromPcap(openFileDialog.FileName);
                NavigationService.Navigate(new Scanner(packets));
            }
        }
    }
}
