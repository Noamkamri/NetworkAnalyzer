using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ScannerServer
{
    public class ProtocolStat : INotifyPropertyChanged // one row for a single protocol, like tcp and its count
    {
        private string _name;
        private int _count;

        public string Name { get => _name; set { _name = value; OnPropertyChanged(); } }
        public int Count { get => _count; set { _count = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class ConnectedAgent : INotifyPropertyChanged
    {
        private string _ip;
        private int _totalPackets;
        private string _status = "Connected";

        public string IP { get => _ip; set { _ip = value; OnPropertyChanged(); } }
        public int TotalPackets { get => _totalPackets; set { _totalPackets = value; OnPropertyChanged(); } }
        public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

        public ObservableCollection<string> AgentAlerts { get; set; } = new ObservableCollection<string>();

        // holds the protocol counts for this agent
        public ObservableCollection<ProtocolStat> Protocols { get; set; } = new ObservableCollection<ProtocolStat>();

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}