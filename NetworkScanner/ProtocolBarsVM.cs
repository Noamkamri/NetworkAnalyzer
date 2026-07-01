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
    // inheriting ObservableValue means the chart animates automatically when Value changes
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

            // series is created once and reused, replacing it would break the animation
            var rowSeries = new RowSeries<ProtocolInfo>
            {
                Values = _data,
                MaxBarWidth = 35,
                Padding = 5,
                DataLabelsPaint = new SolidColorPaint(SKColors.White),
                DataLabelsPosition = DataLabelsPosition.End,

                // x is the packet count, y is the current position in the sorted array.
                // when we re-sort, the index changes and livecharts animates the bar moving up or down
                Mapping = (item, index) => new Coordinate(item.Value ?? 0, index),

                DataLabelsFormatter = p =>
                {
                    var item = (ProtocolInfo)p.Context.DataSource;
                    return $"{item.Name} ({item.Value})";
                }
            };

            // can't set per-bar color directly in the series, so we hook into PointMeasured to do it
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
                var s = _snapshotProvider();

                // update values in place instead of creating new objects, otherwise the animation resets
                UpdateValue("TCP", s.TCP);
                UpdateValue("UDP", s.UDP);
                UpdateValue("HTTP", s.HTTP);
                UpdateValue("HTTPS", s.HTTPS);
                UpdateValue("ARP", s.ARP);
                UpdateValue("ICMP", s.ICMP);
                UpdateValue("DHCP", s.DHCP);
                UpdateValue("DNS", s.DNS);

                // re-sort so the bar with the most packets floats to the top
                _data = _data.OrderBy(x => x.Value).ToArray();

                // reassign Values to tell livecharts the order changed and trigger the race animation
                Series[0].Values = _data;

                await Task.Delay(250); // protocols chart refreshes 4 times a second
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

        // starts everything at 0 so the chart shows all bars immediately, even before any traffic
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