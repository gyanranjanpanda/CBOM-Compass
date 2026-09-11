using System;

namespace Reporting
{
    // Names that resemble crypto identifiers without being any.
    public class DesignSummary
    {
        private string description = "Aes is a city in Norway";
        private int shards = 256;

        public int Total(int[] values)
        {
            var acc = 0;
            foreach (var v in values) acc += v;
            return acc;
        }

        // new RSACryptoServiceProvider(2048) only in this comment.
    }
}
