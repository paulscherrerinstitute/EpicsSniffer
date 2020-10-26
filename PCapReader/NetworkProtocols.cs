using System;
using System.Collections.Generic;
using System.Text;

namespace PCapReader
{
    public enum NetworkProtocols : ushort
    {
        DHCP_SOURCE=68,
        DHCP_DEST=67,
        DNS=53,
        NTP=123,
        BROWSER=138,
        MDNS = 5353,
        SSDP = 1900,
    }
}
