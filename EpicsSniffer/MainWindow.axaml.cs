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
        private Panel detailContainer;
        private TextBox txtFilter;

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
            detailContainer = this.FindControl<Panel>("detailContainer");
            txtFilter = this.FindControl<TextBox>("txtFilter");
            this.KeyDown += MainWindow_KeyDown;
        }

        private void MainWindow_KeyDown(object sender, Avalonia.Input.KeyEventArgs e)
        {
            if (e.Key == Avalonia.Input.Key.Down)
            {
                var items = scrollPanel.Children.Cast<PacketListItem>().ToList();
                if (seletedItem == null && items.Count() != 0)
                {
                    items.First().Select();
                }
                else if (seletedItem != null)
                {
                    for (int i = 0; i < items.Count(); i++)
                        if (items[i] == seletedItem)
                        {
                            i++;
                            if (i >= items.Count())
                                break;
                            items[i].Select();
                            seletedItem.BringIntoView();
                            break;
                        }
                }
            }
            else if (e.Key == Avalonia.Input.Key.Up)
            {
                var items = scrollPanel.Children.Cast<PacketListItem>().ToList();
                if (seletedItem == null && items.Count() != 0)
                {
                    items.First().Select();
                }
                else if (seletedItem != null)
                {
                    for (int i = 0; i < items.Count(); i++)
                        if (items[i] == seletedItem)
                        {
                            i--;
                            if (i < 0)
                                break;
                            items[i].Select();
                            seletedItem.BringIntoView();
                            break;
                        }
                }
            }
        }

        private void LoadFile(string filename)
        {
            using (var pCap = new PCapFile(new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            {

                DataPackets = pCap.Where(p => p.PacketType != PCapPacketType.Other && !(p.IsBaseIpProtocol
                    || (p.PortSource == 0 && p.PortDestination == 0)
                    || p.Data == null
                    || p.Data.Length == 0)).ToList();

                txtFilter.Text = "";
                ShowDataPacket();
            }
        }

        private void ShowDataPacket()
        {
            var filter = txtFilter.Text.ToLower();
            var source = DataPackets.Where(row => row.Source.Contains(filter) || row.Destination.Contains(filter) || row.PacketType.ToString().ToLower().Contains(filter) || row.PacketNumber.ToString().Contains(filter));

            scrollPanel.Children.Clear();
            detailContainer.Children.Clear();
            seletedItem = null;
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

        private void Filter_Changed(object sender, Avalonia.Input.KeyEventArgs e)
        {
            ShowDataPacket();
        }

        private IBrush Colorize(byte[] data)
        {
            if (data.Length < 2)
                return Brushes.Black;
            if (data[0] != 0xCA)
                return Brushes.Black;
            if ((data[2] & (1 << 6)) == 0)
                return Brushes.DarkGreen;
            return Brushes.DarkRed;
        }

        PacketListItem seletedItem = null;

        public List<PCapPacket> DataPackets { get; private set; }

        private void Item_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (seletedItem != null)
                seletedItem.Selected = false;
            seletedItem = (PacketListItem)sender;
            detailContainer.Children.Clear();
            if (seletedItem.Packet.Data[0] == 0xCA) // Pv Packet
            {
                foreach (var pvPacket in PvPacket.Split(seletedItem.Packet.Data))
                {
                    detailContainer.Children.Add(new PvDetails
                    {
                        Source = seletedItem.Packet.Source,
                        Destination = seletedItem.Packet.Destination,
                        Command = $"0x{(int)pvPacket.Command:X2} {pvPacket.Command.ToString()}",
                        Flags = pvPacket.Flag.ToString(),
                        PayloadSize = pvPacket.Data.Length - 8
                    });
                    detailContainer.Children.Add(new HexViewer { Data = pvPacket.Data });
                }
            }
            else
            {
                detailContainer.Children.Add(new HexViewer { Data = seletedItem.Packet.Data });
            }

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
