using SharpPcap;
using System.Collections.Concurrent;

namespace NetworkScanner
{
    public static class PacketQueue
    {
        // יותר קטן = פחות "פאקטות ישנות" שיוצגו באיחור
        public const int Capacity = 6000;

        // כשעוברים את זה – ננקה ישנות כדי לחזור ל-real time
        public const int HighWatermark = 5000;
        public const int LowWatermark = 2000;

        public static BlockingCollection<RawCapture> Queue =
            new BlockingCollection<RawCapture>(boundedCapacity: Capacity);

        public static void TrimIfBacklogged()
        {
            if (Queue.Count <= HighWatermark) return;

            // נזרוק ישנות עד שנרד ל-LowWatermark
            while (Queue.Count > LowWatermark && Queue.TryTake(out _)) { }
        }
    }
}
