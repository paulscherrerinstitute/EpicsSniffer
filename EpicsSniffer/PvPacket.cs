using System;
using System.Collections.Generic;
using System.Text;

namespace EpicsSniffer
{
    [Flags]
    enum PvPacketFlags : int
    {
        ApplicationMessage = 1,
        ControlMessage = 2,
        NotSegmented = 4,
        FirstMessage = 8,
        LastMessage = 16,
        MiddleMessage = 32,
        FromClient = 64,
        FromServer = 128,
        LittleEndian = 256,
        BigEndian = 512
    }

    class PvPacket
    {
        public byte[] Data { get; set; }

        bool IsBigEndian => ((Data[2] & (1 << 7)) != 0);
        bool IsFromServer => ((Data[2] & (1 << 6)) != 0);

        public int Command => Data[3];

        public uint ReadUInt32(int offset)
        {
            return PvPacket.ReadUInt32(Data, IsBigEndian, offset);
        }

        public PvPacketFlags Flag
        {
            get
            {
                var result =
                    ((Data[2] & 1) == 0 ? PvPacketFlags.ApplicationMessage : PvPacketFlags.ControlMessage) |
                    ((Data[2] & (1 << 6)) == 0 ? PvPacketFlags.FromClient : PvPacketFlags.FromServer) |
                    ((Data[2] & (1 << 7)) == 0 ? PvPacketFlags.LittleEndian : PvPacketFlags.BigEndian);

                var segment = (Data[2] & 0b110000) >> 4;
                switch (segment)
                {
                    case 0b00:
                        result |= PvPacketFlags.NotSegmented;
                        break;
                    case 0b01:
                        result |= PvPacketFlags.FirstMessage;
                        break;
                    case 0b10:
                        result |= PvPacketFlags.LastMessage;
                        break;
                    case 0b11:
                        result |= PvPacketFlags.MiddleMessage;
                        break;
                }
                return result;
            }
        }

        private static uint ReadUInt32(byte[] data, bool isBigEndian, int offset)
        {
            if (isBigEndian)
                return ((uint)data[0 + offset] << 24) | ((uint)data[1 + offset] << 16) | ((uint)data[2 + offset] << 8) | data[3 + offset];

            else
                return ((uint)data[3 + offset] << 24) | ((uint)data[2 + offset] << 16) | ((uint)data[1 + offset] << 8) | data[0 + offset];
        }

        public static IEnumerable<PvPacket> Split(byte[] data)
        {
            var bigEndian = ((data[2] & (1 << 7)) != 0);
            uint offset = 0;
            while (offset < data.Length)
            {
                var len = ReadUInt32(data, bigEndian, (int)(offset + 4)) + 8; // 8 header + payload Size
                var subData = new byte[len];
                Array.Copy(data, offset, subData, 0, len);
                offset += len;
                yield return new PvPacket { Data = subData };
            }
        }
    }
}
