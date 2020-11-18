using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PCapReader
{
    class PCapStream : IDisposable
    {
        private bool isBigEndian = false;
        //private Stream BaseStream;
        private BinaryReader reader;
        private bool isDisposed = false;

        public Stream BaseStream { get; private set; }

        public PCapStream(Stream stream)
        {
            this.BaseStream = stream;
            reader = new BinaryReader(this.BaseStream);
            if (reader.ReadUInt32() == 0xA1B2C3D4) // Check the magic and the endian
                isBigEndian = false;
            else
            {
                stream.Seek(0, SeekOrigin.Begin);
                isBigEndian = true;
                if (ReadUInt32() != 0xA1B2C3D4)
                    throw new FileFormatException("Magic header not found.");
            }
        }

        public bool IsEndOfStream => BaseStream.Position >= BaseStream.Length;

        public uint ReadBigEndianUInt32()
        {
            var bytes = reader.ReadBytes(4);
            return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        }

        public uint ReadUInt32()
        {
            if (isBigEndian)
                return ReadBigEndianUInt32();
            else
                return reader.ReadUInt32();
        }

        public int ReadInt32()
        {
            if (isBigEndian)
            {
                var bytes = reader.ReadBytes(4);
                return ((int)bytes[0] << 24) | ((int)bytes[1] << 16) | ((int)bytes[2] << 8) | bytes[3];
            }
            else
                return reader.ReadInt32();
        }

        public ushort ReadBigEndianUInt16()
        {
            var bytes = reader.ReadBytes(2);
            return (ushort)(((uint)bytes[0] << 8) | (uint)bytes[1]);
        }

        public ushort ReadUInt16()
        {
            if (isBigEndian)
                return ReadBigEndianUInt16();
            else
                return reader.ReadUInt16();
        }

        public short ReadInt16()
        {
            if (isBigEndian)
            {
                var bytes = reader.ReadBytes(2);
                return (short)(((int)bytes[0] << 8) | (int)bytes[1]);
            }
            else
                return reader.ReadInt16();
        }

        public byte[] ReadBytes(int nbBytes)
        {
            return reader.ReadBytes(nbBytes);
        }

        public byte ReadByte()
        {
            return reader.ReadByte();
        }

        public void Dispose()
        {
            if (isDisposed)
                return;
            isDisposed = true;
            reader.Dispose();
            BaseStream.Dispose();
        }
    }
}
