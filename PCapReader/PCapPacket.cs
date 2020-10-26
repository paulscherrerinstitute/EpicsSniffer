﻿using System;

namespace PCapReader
{
    public class PCapPacket
    {
        public uint TimeStampSeconds { get; set; }
        public uint TimeStampMicroseconds { get; set; }
        public uint IncludedLength { get; set; }
        public uint ActualLength { get; set; }
        public byte[] DestinationMac { get; set; }
        public byte[] SourceMac { get; set; }
        public ushort EthernetType { get; set; }
        public int PacketNumber { get; set; }
        public byte[] IpSource { get; set; }
        public byte[] IpDestination { get; set; }
        public ushort PortSource { get; set; }
        public ushort PortDestination { get; set; }
        public PCapPacketType PacketType { get; set; }
        public bool IsBaseIpProtocol =>
            (Enum.IsDefined(typeof(NetworkProtocols), PortDestination)
                || Enum.IsDefined(typeof(NetworkProtocols), PortSource));

        public byte[] Data { get; internal set; }
        public object SequenceNumber { get; internal set; }
        public uint AcknowledgmentNumber { get; internal set; }
        public byte[] Flags { get; internal set; }
    }
}