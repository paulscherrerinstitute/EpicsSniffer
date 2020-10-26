using PCapReader;
using System;
using System.IO;

namespace PCapReadTest
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var pCap = new PCapFile(new FileStream("network.pcap", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            {
                while (pCap.HasPacket)
                {
                    var packet = pCap.Next();
                    if (packet.PacketType == PCapPacketType.Other)
                        continue;
                    if (packet.IsBaseIpProtocol || (packet.PortSource == 0 && packet.PortDestination == 0) || packet.Data == null || packet.Data.Length == 0)
                        continue;

                    Console.WriteLine($"Packet: {packet.PacketNumber}, Type: {packet.PacketType}, SourcePort: {packet.PortSource}, DestPort: {packet.PortDestination}, Len: {packet.Data.Length}");
                }
            }
        }
    }
}
