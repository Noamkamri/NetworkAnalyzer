using SharpPcap;
using System.Collections.Concurrent;

namespace NetworkScanner
{
    public static class PacketQueue
    {
        // max packets that can sit waiting to be processed, keeping this bounded prevents memory from blowing up
        public const int Capacity = 6000;

        // if the queue grows past this we know we're falling behind real time
        public const int HighWatermark = 5000;
        // once we drain back down to this we're considered caught up again
        public const int LowWatermark = 2000;

        public static BlockingCollection<RawCapture> Queue =
            new BlockingCollection<RawCapture>(boundedCapacity: Capacity);

    }
}
