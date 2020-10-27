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
        private Panel scrollPanel;
        private HexViewer hexViewer;

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

            scrollPanel = this.FindControl<Panel>("scrollPanel");
            hexViewer = this.FindControl<HexViewer>("hexViewer");

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
                    Packet = p
                }));
                foreach (var item in scrollPanel.Children.Cast<PacketListItem>())
                    item.Click += Item_Click;
            }
        }

        PacketListItem seletedItem = null;

        private void Item_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (seletedItem != null)
                seletedItem.Selected = false;
            seletedItem = (PacketListItem)sender;
            hexViewer.Data = seletedItem.Packet.Data;
            seletedItem.Selected = true;
        }
    }
}
