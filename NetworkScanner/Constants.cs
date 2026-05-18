using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkScanner
{
    public class Constants
    {   
        // SYN & ICMP Flood Prevention:
        public const int MAX_SYN_PER_SECOND = 10;
        public const int MAX_ICMP_PER_SECOND = 5;

    }
}
