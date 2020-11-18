using System;
using System.IO;
using System.Net;

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


        public string Source => new IPAddress(IpSource).ToString() + "@" + PortSource;
        public string Destination => new IPAddress(IpDestination).ToString() + "@" + PortDestination;

        public PCapPacketType PacketType { get; set; }
        public bool IsBaseIpProtocol =>
            (Enum.IsDefined(typeof(NetworkProtocols), PortDestination)
                || Enum.IsDefined(typeof(NetworkProtocols), PortSource));

        public byte[] Data { get; internal set; }
        public object SequenceNumber { get; internal set; }
        public uint AcknowledgmentNumber { get; internal set; }
        public byte[] Flags { get; internal set; }

        private static uint ReadBigEndianUInt32(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(4);
            return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        }

        private static ushort ReadBigEndianUInt16(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(2);
            return (ushort)(((uint)bytes[0] << 8) | (uint)bytes[1]);
        }

        public static PCapPacket DecodeIP4(byte[] data, byte byVersionAndHeaderLength, int size, PCapPacket result = null)
        {
            using (var stream = new BinaryReader(new MemoryStream(data)))
            {
                return DecodeIP4(stream, byVersionAndHeaderLength, size, result);
            }
        }

        public static PCapPacket DecodeIP4(BinaryReader stream, byte byVersionAndHeaderLength, int size, PCapPacket result = null)
        {
            if (result == null)
                result = new PCapPacket();

            //The next eight bits contain the Differentiated services
            var byDifferentiatedServices = stream.ReadByte();
            //Next eight bits hold the total length of the datagram
            var usTotalLength = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            //Next sixteen have the identification bytes
            var usIdentification = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            //Next sixteen bits contain the flags and fragmentation offset
            var usFlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            //Next eight bits have the TTL value
            var byTTL = stream.ReadByte();

            /*//Next eight represent the protocol encapsulated in the datagram
            var byProtocol = stream.ReadByte();

            //Next sixteen bits contain the checksum of the header
            var sChecksum = IPAddress.NetworkToHostOrder(stream.ReadInt16());

            //Next thirty two bits have the source IP address
            var uiSourceIPAddress = (uint)(stream.ReadInt32());

            //Next thirty two hold the destination IP address
            var uiDestinationIPAddress = (uint)(stream.ReadInt32());*/

            //Now we calculate the header length
            var byHeaderLength = byVersionAndHeaderLength;
            //The last four bits of the version and header length field contain the
            //header length, we perform some simple binary arithmetic operations to
            //extract them
            byHeaderLength <<= 4;
            byHeaderLength >>= 4;
            //Multiply by four to get the exact header length
            byHeaderLength *= 4;


            // Skip TCP/IP Header
            //stream.ReadBytes(9);
            var protocolType = stream.ReadByte();
            if (protocolType == 0x11) // UDP
            {
                stream.ReadBytes(2); // Checksum
                result.IpSource = stream.ReadBytes(4);
                result.IpDestination = stream.ReadBytes(4);
                result.PortSource = ReadBigEndianUInt16(stream);
                result.PortDestination = ReadBigEndianUInt16(stream);
                result.PacketType = PCapPacketType.UDP;

                var udpLength = ReadBigEndianUInt16(stream) - 8;
                ReadBigEndianUInt16(stream); // Checksum
                result.Data = stream.ReadBytes(udpLength);
                // Skip to end
            }
            else if (protocolType == 0x6) // TCP
            {
                stream.ReadBytes(2); // Checksum
                result.IpSource = stream.ReadBytes(4);
                result.IpDestination = stream.ReadBytes(4);
                result.PortSource = ReadBigEndianUInt16(stream);
                result.PortDestination = ReadBigEndianUInt16(stream);
                result.PacketType = PCapPacketType.TCP;

                result.SequenceNumber = ReadBigEndianUInt32(stream);
                result.AcknowledgmentNumber = ReadBigEndianUInt32(stream);
                result.Flags = stream.ReadBytes(2);
                var windowSize = ReadBigEndianUInt16(stream);
                stream.ReadBytes(2); // checksum
                stream.ReadBytes(2); // urgent pointer
                var dataOffset = ((result.Flags[0] & 0b11110000) >> 4) * 4 - 20;

                if (dataOffset >= 0)
                {
                    stream.ReadBytes(dataOffset); // Skip offset
                    if (size - (38 + 16 + dataOffset) > 0)
                        result.Data = stream.ReadBytes(size - (38 + 16 + dataOffset));
                }
            }
            else
            {
                result.PacketType = PCapPacketType.Other;
            }
            return result;
        }
        public static PCapPacket DecodeIP6(byte[] data, byte byVersionAndHeaderLength, int size, PCapPacket result = null)
        {
            using (var stream = new BinaryReader(new MemoryStream(data)))
            {
                return DecodeIP6(stream, byVersionAndHeaderLength, size, result);
            }
        }


        public static PCapPacket DecodeIP6(BinaryReader stream, byte byVersionAndHeaderLength, int size, PCapPacket result = null)
        {
            if (result == null)
                result = new PCapPacket();

            //The next eight bits contain the Differentiated services
            var byDifferentiatedServices = stream.ReadBytes(3);
            //Next eight bits hold the total length of the datagram
            var payloadLength = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            var nextHeader = stream.ReadByte();
            var hopLimi = stream.ReadByte();

            result.IpSource = stream.ReadBytes(16);
            result.IpDestination = stream.ReadBytes(16);
            result.PacketType = PCapPacketType.Other;

            while (nextHeader != 59)
            {
                switch (nextHeader)
                {
                    case 60: // Destination options
                    case 0: // Hop-by-hop
                        nextHeader = stream.ReadByte();
                        stream.ReadBytes(15); // Skip header
                        payloadLength -= 16;
                        break;
                    case 43: // Routing
                        nextHeader = stream.ReadByte();
                        stream.ReadBytes(15); // Skip header
                        payloadLength -= 16;
                        break;
                    case 44: // Fragment
                        nextHeader = stream.ReadByte();
                        stream.ReadBytes(7); // Skip header
                        payloadLength -= 8;
                        break;
                    case 17: // UDP
                        result.PacketType = PCapPacketType.UDP;
                        result.PortSource = ReadBigEndianUInt16(stream);
                        result.PortDestination = ReadBigEndianUInt16(stream);
                        var udpLength = ReadBigEndianUInt16(stream) - 8;
                        ReadBigEndianUInt16(stream); // Checksum

                        result.Data = stream.ReadBytes(udpLength);
                        return result;
                    case 6: // TCP
                        result.PortSource = ReadBigEndianUInt16(stream);
                        result.PortDestination = ReadBigEndianUInt16(stream);
                        result.PacketType = PCapPacketType.TCP;

                        result.SequenceNumber = ReadBigEndianUInt32(stream);
                        result.AcknowledgmentNumber = ReadBigEndianUInt32(stream);
                        result.Flags = stream.ReadBytes(2);
                        var windowSize = ReadBigEndianUInt16(stream);
                        stream.ReadBytes(2); // checksum
                        stream.ReadBytes(2); // urgent pointer
                        var dataOffset = ((result.Flags[0] & 0b11110000) >> 4) * 4 - 20;

                        if (dataOffset >= 0)
                        {
                            stream.ReadBytes(dataOffset); // Skip offset
                            if (payloadLength - (20 + dataOffset) > 0)
                                result.Data = stream.ReadBytes(payloadLength - (20 + dataOffset));
                        }
                        return result;
                    default:
                        nextHeader = 59; // No next
                        break;
                }
            }
            return result;
        }

        public static PCapPacket CreateFromBytes(byte[] data, int size)
        {
            using (var stream = new BinaryReader(new MemoryStream(data)))
            {
                /*result.DestinationMac = stream.ReadBytes(6);
                result.SourceMac = stream.ReadBytes(6);
                result.EthernetType = stream.ReadUInt16();*/

                //The first eight bits of the IP header contain the version and
                //header length so we read them
                var byVersionAndHeaderLength = stream.ReadByte();

                if ((byVersionAndHeaderLength & 0b1111) == 6) // IP 6
                    return DecodeIP6(stream, byVersionAndHeaderLength, size);
                else
                    return DecodeIP4(stream, byVersionAndHeaderLength, size);
            }
        }
    }
}