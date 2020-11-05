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

    enum PvCommand : int
    {
        Beacon = 0x0,
        ConnectionValidation = 0x1,
        Echo = 0x2,
        Search = 0x3,
        SearchResponse = 0x4,
        Auth = 0x5,
        AclChange = 0x6,
        CreateChannel = 0x7,
        DestroyChannel = 0x8,
        ConnectionValidated = 0x9,
        Get = 0xA,
        Put = 0xB,
        PutGet = 0xC,
        Monitor = 0xD,
        Array = 0xE,
        DestroyRequest = 0xF,
        Process = 0x10,
        GetField = 0x11,
        Message = 0x12,
        MultipleData = 0x13,
        RPC = 0x14,
        CancelRequest = 0x15,
        OriginTag = 0x16
    }

    class PvPacket
    {
        public byte[] Data { get; set; }

        bool IsBigEndian => ((Data[2] & (1 << 7)) != 0);
        bool IsFromServer => ((Data[2] & (1 << 6)) != 0);

        public PvCommand Command => (PvCommand)Data[3];

        public uint ReadUInt32(int offset)
        {
            return PvPacket.ReadUInt32(Data, IsBigEndian, offset);
        }

        public ushort ReadUInt16(int offset)
        {
            return PvPacket.ReadUInt16(Data, IsBigEndian, offset);
        }

        public string ReadString(int offset)
        {
            var nb = Data[offset];
            var strData = new byte[nb];
            Array.Copy(Data, offset + 1, strData, 0, nb);
            return ASCIIEncoding.ASCII.GetString(strData);
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

        private static ushort ReadUInt16(byte[] data, bool isBigEndian, int offset)
        {
            if (isBigEndian)
                return (ushort)(((uint)data[0 + offset] << 8) | data[1 + offset]);

            else
                return (ushort)(((uint)data[1 + offset] << 8) | data[0 + offset]);
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
