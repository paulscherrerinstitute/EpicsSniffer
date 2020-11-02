using PCapReader;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EpicsSniffer
{
    class NetworkSniffer : IDisposable
    {
        private Socket mainSocket;
        private byte[] byteData = new byte[65000];
        DateTime start = DateTime.UtcNow;
        int packetNumber = 0;

        public NetworkSniffer(string ipAddress)
        {
            mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw,
                                   ProtocolType.IP);

            // Bind the socket to the selected IP address
            mainSocket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), 0));

            // Set the socket options
            mainSocket.SetSocketOption(SocketOptionLevel.IP,  //Applies only to IP packets
                                       SocketOptionName.HeaderIncluded, //Set the include header
                                       true);                           //option to true

            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byOut = new byte[4];

            //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
            mainSocket.IOControl(IOControlCode.ReceiveAll,  //SIO_RCVALL of Winsock
                                 byTrue, byOut);

            //Start receiving the packets asynchronously
            mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }

        public void Dispose()
        {
            mainSocket.Close();
            mainSocket = null;
        }

        private void OnReceive(IAsyncResult ar)
        {
            int size = 0;

            try
            {
                size = mainSocket.EndReceive(ar);
            }
            catch (ObjectDisposedException)
            {
                // Stop receiving
                return;
            }

            var newPacket = PCapPacket.CreateFromBytes(byteData, size);
            newPacket.PacketNumber = packetNumber++;
            var diff = DateTime.UtcNow - start;
            newPacket.TimeStampSeconds = (uint)diff.TotalSeconds;
            newPacket.TimeStampMicroseconds = (uint)((diff.TotalSeconds - (uint)diff.TotalSeconds) * 1000000);
            ReceivedPacket?.Invoke(this, newPacket);

            // Receive again
            try
            {
                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            }
            catch (ObjectDisposedException)
            {
                // Stop receiving
                return;
            }
        }

        public delegate void ReceivedPacketDelegate(NetworkSniffer sniffer, PCapPacket packet);
        public event ReceivedPacketDelegate ReceivedPacket;
    }
}
