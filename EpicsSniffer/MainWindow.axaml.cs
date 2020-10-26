using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using PCapReader;
using System.IO;
using System.Linq;

namespace EpicsSniffer
{
    public class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);

            var scrollPanel = this.FindControl<Panel>("scrollPanel");

            using (var pCap = new PCapFile(new FileStream("network.pcap", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            {
                var source = pCap.Where(p => p.PacketType != PCapPacketType.Other && !(p.IsBaseIpProtocol
                    || (p.PortSource == 0 && p.PortDestination == 0)
                    || p.Data == null
                    || p.Data.Length == 0));
                scrollPanel.Children.AddRange(source.Select(p => new PacketListItem
                {
                    PacketNumber = p.PacketNumber,
                    PacketSource = p.Source,
                    PacketDestination = p.Destination,
                    PacketProtocol = p.PacketType.ToString(),
                    PacketLength = p.Data.Length,
                }));
            }
        }
    }
}
