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
using System.Threading;

namespace EpicsSniffer
{
    public class MainWindow : Window
    {
        private Panel scrollPanel;
        private Panel detailContainer;
        private TextBox txtFilter;
        private MenuItem mnuStopCapture;
        private SearchStats searchStats;
        private NetworkSniffer sniffer;

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
            mnuStopCapture = this.FindControl<MenuItem>("mnuStopCapture");
            searchStats = this.FindControl<SearchStats>("searchStats");
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
                lock (DataPacketsLock)
                {
                    DataPackets = pCap.Where(p => p.PacketType != PCapPacketType.Other && !(p.IsBaseIpProtocol
                    || (p.PortSource == 0 && p.PortDestination == 0)
                    || p.Data == null
                    || p.Data.Length == 0)).ToList();

                    // Clear statistics
                    searchStats.Clear();
                    DataPackets.ForEach(row =>
                    {
                        if (SearchStats.IsSearchPacket(row)) searchStats.Add(row);
                    });
                }
                txtFilter.Text = "";
                ShowDataPacket();
            }
        }

        private void ShowDataPacket()
        {
            var filter = txtFilter.Text?.ToLower() ?? "";
            List<PCapPacket> source;
            lock (DataPacketsLock)
            {
                source = DataPackets.Where(row => row.Source.Contains(filter)
                         || row.Destination.Contains(filter)
                         || row.PacketType.ToString().ToLower().Contains(filter)
                         || row.PacketNumber.ToString().Contains(filter))
                    .ToList();
            }

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
            if (data.Length < 3)
                return Brushes.Black;
            if (data[0] != 0xCA)
                return Brushes.Black;
            if ((data[2] & (1 << 6)) == 0)
                return Brushes.DarkGreen;
            return Brushes.DarkRed;
        }

        PacketListItem seletedItem = null;

        public List<PCapPacket> DataPackets { get; private set; }
        public object DataPacketsLock = new object();

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

        private void Menu_Capture(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var capture = new CaptureWindow();
            capture.ShowDialog<string>(this).ContinueWith(result =>
            {
                if (result.Result == null)
                    return;
                if (sniffer != null)
                {
                    sniffer.ReceivedPacket -= Sniffer_ReceivedPacket;
                    sniffer.Dispose();
                }
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    searchStats.Clear();

                    try
                    {
                        sniffer = new NetworkSniffer(result.Result);
                    }
                    catch (System.Net.Sockets.SocketException ex)
                    {
                        if (sniffer != null)
                            sniffer.Dispose();
                        sniffer = null;

                        //Console.WriteLine(ex.ToString());
                        if (ex.NativeErrorCode == 10049)//  ex.Message == "The requested address is not valid in its context."
                        {
                            var dlg = new AdminRightsRequired { Message = "Impossible to bind to this network interface.", Title = "Wrong network interface" };
                            dlg.ShowDialog(this);
                        }
                        else if (ex.NativeErrorCode == 10013)
                        {
                            var dlg = new AdminRightsRequired();
                            dlg.ShowDialog(this);
                        }
                        else
                        {
                            var dlg = new AdminRightsRequired { Message = ex.Message, Title = "Error while binding" };
                            dlg.ShowDialog(this);
                        }

                    }
                    if (sniffer != null)
                    {
                        sniffer.ReceivedPacket += Sniffer_ReceivedPacket;
                        DataPackets = new List<PCapPacket>();
                        ShowDataPacket();
                        mnuStopCapture.IsEnabled = true;
                    }
                });
            });
        }

        private void Sniffer_ReceivedPacket(NetworkSniffer sniffer, PCapPacket packet)
        {
            if (DataPackets == null)
                DataPackets = new List<PCapPacket>();
            if (packet.PacketType != PCapPacketType.Other && !(packet.IsBaseIpProtocol
                               || (packet.PortSource == 0 && packet.PortDestination == 0)
                               || packet.Data == null
                               || packet.Data.Length == 0))
            {
                lock (DataPacketsLock)
                {
                    DataPackets.Add(packet);
                }

                if (SearchStats.IsSearchPacket(packet))
                    searchStats.Add(packet);

                // Does the new packet match the filter?
                var filter = txtFilter.Text?.ToLower() ?? "";
                if (packet.Source.Contains(filter)
                         || packet.Destination.Contains(filter)
                         || packet.PacketType.ToString().ToLower().Contains(filter)
                         || packet.PacketNumber.ToString().Contains(filter))
                {
                    Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    {
                        var item = new PacketListItem
                        {
                            PacketNumber = packet.PacketNumber,
                            PacketSource = packet.Source,
                            PacketDestination = packet.Destination,
                            PacketProtocol = packet.PacketType.ToString(),
                            PacketLength = packet.Data.Length,
                            Packet = packet,
                            Foreground = Colorize(packet.Data)
                        };
                        item.Click += Item_Click;
                        scrollPanel.Children.Add(item);
                    });
                }
            }
        }

        private void Menu_StopCapture(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            mnuStopCapture.IsEnabled = false;
            if (sniffer != null)
            {
                sniffer.ReceivedPacket -= Sniffer_ReceivedPacket;
                sniffer.Dispose();
            }
            sniffer = null;
        }

        private void Menu_Open(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var open = new OpenFileDialog();
            open.Filters.Add(new FileDialogFilter { Name = "PCAP", Extensions = new List<string> { "pcap" } });
            open.ShowAsync(this).ContinueWith(files =>
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (files == null || files.Result == null || files.Result.Length == 0)
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
            var fullData = seletedItem.Packet.Data;

            var fullText = new StringBuilder();

            foreach (var p in PvPacket.Split(fullData))
            {
                if (fullText.Length != 0)
                    fullText.Append("\n\n");

                var data = p.Data;

                var hex = new StringBuilder();
                var chars = new StringBuilder();
                var posString = new StringBuilder();

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
            }
            Application.Current.Clipboard.SetTextAsync(fullText.ToString());
        }

        private void Menu_CopyBytes(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (seletedItem == null)
                return;
            var fullData = seletedItem.Packet.Data;

            var fullText = new StringBuilder();

            foreach (var p in PvPacket.Split(fullData))
            {
                if (fullText.Length != 0)
                    fullText.Append("\n\n");

                var data = p.Data;

                fullText.Append("var data=new byte[]{");
                int pos = 0;
                foreach (var b in data)
                {
                    if (pos != 0)
                        fullText.Append(", ");
                    fullText.Append($"0x{b:X2}");
                    pos++;
                }
                fullText.Append("};\n");
            }
            Application.Current.Clipboard.SetTextAsync(fullText.ToString());
        }
    }
}
