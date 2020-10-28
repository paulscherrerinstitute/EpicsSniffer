using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using PCapReader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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

            LoadFile("network.pcap");
        }

        private void LoadFile(string filename)
        {
            using (var pCap = new PCapFile(new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            {
                scrollPanel.Children.Clear();
                seletedItem = null;

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
                    Packet = p,
                    Foreground = Colorize(p.Data)
                }));
                foreach (var item in scrollPanel.Children.Cast<PacketListItem>())
                    item.Click += Item_Click;
            }
        }

        private IBrush Colorize(byte[] data)
        {
            if (data.Length < 2)
                return Brushes.Black;
            if (data[0] != 0xCA)
                return Brushes.Black;
            if(data[3] == 0x03)
                return Brushes.DarkGreen;
            return Brushes.DarkRed;
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
        private void Menu_Open(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var open = new OpenFileDialog();
            open.Filters.Add(new FileDialogFilter { Name = "PCAP", Extensions = new List<string> { "pcap" } });
            open.ShowAsync(this).ContinueWith(files =>
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (files.Result.Length == 0)
                        return;
                    LoadFile(files.Result.First());
                });
            });
        }
        private void Menu_Exit(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            this.Close();
        }

        private void Menu_Copy(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (seletedItem == null)
                return;
            var data = seletedItem.Packet.Data;

            var hex = new StringBuilder();
            var chars = new StringBuilder();
            var posString = new StringBuilder();
            var fullText = new StringBuilder();

            int nbInRow = 0;
            int pos = 0;
            foreach (var b in data)
            {
                if (nbInRow == 0)
                    posString.Append($"{pos:X4}");
                else
                    hex.Append(' ');
                if (nbInRow == 8)
                {
                    hex.Append(" ");
                    chars.Append(" ");
                }
                if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '1' && b <= '0') || ",;:+\"*%&/()=?^~[]{}§-_".Contains((char)b))
                    chars.Append((char)b);
                else
                    chars.Append('.');
                hex.Append($"{b:X2}");
                nbInRow++;
                pos++;
                if (nbInRow >= 16)
                {
                    nbInRow = 0;
                    fullText.Append(posString.ToString());
                    fullText.Append("    ");
                    fullText.Append(hex.ToString());
                    fullText.Append("  ");
                    fullText.Append(chars.ToString());
                    fullText.Append("\n");

                    posString.Clear();
                    hex.Clear();
                    chars.Clear();
                }
            }

            if (posString.ToString().Length > 0)
            {
                fullText.Append(posString.ToString());
                fullText.Append("    ");
                fullText.Append(hex.ToString());
                fullText.Append(new string(' ', 48 - hex.ToString().Length));
                fullText.Append("  ");
                fullText.Append(chars.ToString());
                fullText.Append("\n");
            }
            Application.Current.Clipboard.SetTextAsync(fullText.ToString());
        }
    }
}
