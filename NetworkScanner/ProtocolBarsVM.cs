using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults; // REQUIRED for ObservableValue
using LiveChartsCore.Kernel;
using LiveChartsCore.Measure;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace NetworkScanner
{
    // 1. Inherit from ObservableValue so the bar width animates automatically
    public class ProtocolInfo : ObservableValue
    {
        public ProtocolInfo(string name, int value, SolidColorPaint paint)
        {
            Name = name;
            Paint = paint;
            Value = value; // Updates the ObservableValue base
        }

        public string Name { get; set; }
        public SolidColorPaint Paint { get; set; }
    }

    public partial class ProtocolBarsVM : ObservableObject
    {
        private readonly Func<Statistics.ProtocolCount> _snapshotProvider;
        private ProtocolInfo[] _data;

        public ProtocolBarsVM(Func<Statistics.ProtocolCount> snapshotProvider)
        {
            _snapshotProvider = snapshotProvider;
            _data = FetchEmpty();

            // 2. Create the Series ONCE. We will not recreate it, just update its Values.
            var rowSeries = new RowSeries<ProtocolInfo>
            {
                Values = _data,
                MaxBarWidth = 35,
                Padding = 5,
                DataLabelsPaint = new SolidColorPaint(SKColors.White),
                DataLabelsPosition = DataLabelsPosition.End,

                // MAPPING: This creates the racing effect.
                // X = Value (Length), Y = Index (Rank in the list)
                Mapping = (item, index) => new Coordinate(item.Value ?? 0, index),

                DataLabelsFormatter = p =>
                {
                    var item = (ProtocolInfo)p.Context.DataSource;
                    return $"{item.Name} ({item.Value})";
                }
            };

            // 3. Apply Colors individually
            rowSeries.PointMeasured += point =>
            {
                if (point.Visual is null || point.Model is null) return;
                point.Visual.Fill = point.Model.Paint;
            };

            Series = new ISeries[] { rowSeries };

            XAxes = new[] { new Axis { MinLimit = 0, IsVisible = false } };
            YAxes = new[] { new Axis { IsVisible = false } }; // We hide Y labels because bar labels show the name

            _ = StartMonitoring();
        }

        public bool IsMonitoring { get; set; } = true;
        public ISeries[] Series { get; set; }
        public Axis[] XAxes { get; set; }
        public Axis[] YAxes { get; set; }

        private async Task StartMonitoring()
        {
            await Task.Delay(1000);

            while (IsMonitoring)
            {
                // A. Get Data from your Statistics class
                var s = _snapshotProvider();

                // B. Update existing objects (Do not create new ones!)
                //    Note: Using the EXACT field names from your Statistics.cs

                //MessageBox.Show(s.UDP.ToString());

                UpdateValue("TCP", s.TCP);
                UpdateValue("UDP", s.UDP);
                UpdateValue("HTTP", s.HTTP);
                UpdateValue("HTTPS", s.HTTPS);
                UpdateValue("ARP", s.ARP);
                UpdateValue("ICMP", s.ICMP);
                UpdateValue("DHCP", s.DHCP);
                UpdateValue("DNS", s.DNS);

                // C. SORT the array
                //    Because we use "Mapping", changing the index triggers the animation.
                _data = _data.OrderBy(x => x.Value).ToArray();

                // D. Tell the chart the order changed
                Series[0].Values = _data;

                await Task.Delay(250);
            }
        }

        private void UpdateValue(string name, int newValue)
        {
            // Find the specific protocol object and update its value
            var item = _data.FirstOrDefault(x => x.Name == name);
            if (item != null)
            {
                item.Value = newValue;
            }
        }

        // Helper to initialize the list with 0 values and correct colors
        private static ProtocolInfo[] FetchEmpty() => new[]
        {
            new ProtocolInfo("TCP",   0, GetPaintByName("TCP")),
            new ProtocolInfo("UDP",   0, GetPaintByName("UDP")),
            new ProtocolInfo("ICMP",  0, GetPaintByName("ICMP")),
            new ProtocolInfo("ARP",   0, GetPaintByName("ARP")),
            new ProtocolInfo("DNS",   0, GetPaintByName("DNS")),
            new ProtocolInfo("DHCP",  0, GetPaintByName("DHCP")),
            new ProtocolInfo("HTTP",  0, GetPaintByName("HTTP")),
            new ProtocolInfo("HTTPS", 0, GetPaintByName("HTTPS")),
        };

        private static SolidColorPaint GetPaintByName(string name) => name switch
        {
            "TCP" => new SolidColorPaint(new SKColor(0x42, 0x7C, 0xE6)), // Blue
            "UDP" => new SolidColorPaint(new SKColor(0x2E, 0xB8, 0x7C)), // Green
            "ICMP" => new SolidColorPaint(new SKColor(0xE2, 0x5D, 0x5D)), // Red
            "ARP" => new SolidColorPaint(new SKColor(0x9B, 0x6B, 0xE9)), // Purple
            "DNS" => new SolidColorPaint(new SKColor(0xE0, 0x4C, 0xAA)), // Pink
            "DHCP" => new SolidColorPaint(new SKColor(0x3B, 0xB1, 0xB9)), // Cyan
            "HTTP" => new SolidColorPaint(new SKColor(0xF2, 0xA1, 0x2A)), // Orange
            "HTTPS" => new SolidColorPaint(new SKColor(0xD6, 0xB5, 0x2A)), // Yellow
            _ => new SolidColorPaint(SKColors.Gray)
        };
    }
}