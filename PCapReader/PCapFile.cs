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
        bool? includeNanosecs = null;

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
            if (result.IncludedLength > result.ActualLength)
                throw new FileFormatException("Included length bigger than actual length");
            //Console.WriteLine("Pk "+ result.PacketNumber+" "+ result.IncludedLength);

            if (result.IncludedLength < 14)
                stream.ReadBytes((int)result.IncludedLength);
            else
            {
                // Check if we must include nanosecs or not
                if (!includeNanosecs.HasValue)
                {
                    var p = stream.BaseStream.Position;
                    includeNanosecs = (stream.ReadBigEndianUInt32() == 0); // Let's hope it starts with 0
                    stream.BaseStream.Seek(p, SeekOrigin.Begin);
                }

                if (includeNanosecs.Value == true)
                    stream.ReadBytes(8);
                result.DestinationMac = stream.ReadBytes(6);
                result.SourceMac = stream.ReadBytes(6);
                result.EthernetType = stream.ReadUInt16();
                Console.WriteLine("Nb: " + result.PacketNumber + ", Type: " + result.EthernetType);

                if (result.EthernetType == 0x8) // IP4
                {
                    var byVersionAndHeaderLength = stream.ReadByte();
                    var bytes = stream.ReadBytes((int)result.IncludedLength - 15);
                    PCapPacket.DecodeIP4(bytes, byVersionAndHeaderLength, bytes.Length, result);
                }
                else if (result.EthernetType == 56710) // IP 6?
                {
                    var byVersionAndHeaderLength = stream.ReadByte();
                    var bytes = stream.ReadBytes((int)result.IncludedLength - 15);
                    PCapPacket.DecodeIP6(bytes, byVersionAndHeaderLength, bytes.Length, result);
                }
                else
                {
                    stream.ReadBytes((int)result.IncludedLength - 14);
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
