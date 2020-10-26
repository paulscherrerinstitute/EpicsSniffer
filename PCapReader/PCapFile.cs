using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PCapReader
{
    public class PCapFile : IDisposable, IEnumerable<PCapPacket>
    {
        bool isDisposed = false;
        public ushort VersionMajor { get; private set; }
        public ushort VersionMinor { get; private set; }
        public int TimeZone { get; private set; }
        public uint Accuracy { get; private set; }
        public uint MaxLength { get; private set; }
        public uint Network { get; private set; }
        private PCapStream stream;
        private int currentPacketNumber = 0;

        public PCapFile(Stream baseStream)
        {
            this.stream = new PCapStream(baseStream);
            VersionMajor = stream.ReadUInt16();
            VersionMinor = stream.ReadUInt16();
            TimeZone = stream.ReadInt32();
            Accuracy = stream.ReadUInt32();
            MaxLength = stream.ReadUInt32();
            Network = stream.ReadUInt32();
        }

        public PCapPacket Next()
        {
            if (stream.IsEndOfStream)
                return null;
            var result = new PCapPacket();
            result.PacketNumber = ++currentPacketNumber;
            result.TimeStampSeconds = stream.ReadUInt32();
            result.TimeStampMicroseconds = stream.ReadUInt32();
            result.IncludedLength = stream.ReadUInt32();
            result.ActualLength = stream.ReadUInt32();

            if (result.IncludedLength < 14)
                stream.ReadBytes((int)result.IncludedLength);
            else
            {
                result.DestinationMac = stream.ReadBytes(6);
                result.SourceMac = stream.ReadBytes(6);
                result.EthernetType = stream.ReadUInt16();

                if (result.EthernetType != 0x8) // Not TCP/IP => we skip
                {
                    stream.ReadBytes((int)result.IncludedLength - 14);
                }
                else
                {
                    // Skip TCP/IP Header
                    stream.ReadBytes(9);
                    var protocolType = stream.ReadByte();
                    if (protocolType == 0x11) // UDP
                    {
                        stream.ReadBytes(2); // Checksum
                        result.IpSource = stream.ReadBytes(4);
                        result.IpDestination = stream.ReadBytes(4);
                        result.PortSource = stream.ReadBigEndianUInt16();
                        result.PortDestination = stream.ReadBigEndianUInt16();
                        result.PacketType = PCapPacketType.UDP;

                        var udpLength = stream.ReadBigEndianUInt16() - 8;
                        stream.ReadBigEndianUInt16(); // Checksum
                        result.Data = stream.ReadBytes(udpLength);
                        // Skip to end
                        stream.ReadBytes((int)result.IncludedLength - (42 + udpLength));
                    }
                    else if (protocolType == 0x6) // TCP
                    {
                        stream.ReadBytes(2); // Checksum
                        result.IpSource = stream.ReadBytes(4);
                        result.IpDestination = stream.ReadBytes(4);
                        result.PortSource = stream.ReadBigEndianUInt16();
                        result.PortDestination = stream.ReadBigEndianUInt16();
                        result.PacketType = PCapPacketType.TCP;

                        result.SequenceNumber = stream.ReadBigEndianUInt32();
                        result.AcknowledgmentNumber = stream.ReadBigEndianUInt32();
                        result.Flags = stream.ReadBytes(2);
                        var windowSize = stream.ReadBigEndianUInt16();
                        stream.ReadBytes(2); // checksum
                        stream.ReadBytes(2); // urgent pointer
                        var dataOffset = ((result.Flags[0] & 0b11110000) >> 4) * 4 - 20;

                        stream.ReadBytes(dataOffset); // Skip offset

                        result.Data = stream.ReadBytes((int)result.IncludedLength - (38 + 16 + dataOffset));
                    }
                    else
                    {
                        result.PacketType = PCapPacketType.Other;
                        stream.ReadBytes((int)result.IncludedLength - 24);
                    }
                }
            }
            return result;
        }

        public bool HasPacket => !stream.IsEndOfStream;

        public void Dispose()
        {
            if (isDisposed)
                return;
            isDisposed = true;
            stream?.Dispose();
        }

        public IEnumerator<PCapPacket> GetEnumerator()
        {
            while (this.HasPacket)
                yield return Next();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            while (this.HasPacket)
                yield return Next();
        }
    }
}
