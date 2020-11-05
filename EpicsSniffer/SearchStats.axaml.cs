using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using PCapReader;
using System;
using System.Collections.Generic;
using System.Linq;

namespace EpicsSniffer
{
    public class SearchStats : UserControl
    {
        private Panel searchScroll;
        private Panel searchStatScroll;
        private Panel sourceStatScroll;
        private List<Search> searches = new List<Search>();
        private object searchLock = new object();

        class Search
        {
            public string Channel { get; set; }
            public string From { get; set; }
            public string Time { get; set; }
        }

        public SearchStats()
        {
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            searchScroll = this.FindControl<Panel>("searchScroll");
            searchStatScroll = this.FindControl<Panel>("searchStatScroll");
            sourceStatScroll = this.FindControl<Panel>("sourceStatScroll");
        }

        public static bool IsSearchPacket(PCapPacket packet)
        {
            return packet.Data[0] == 0xCA && packet.Data[3] == 0x3;
        }

        public void Add(PCapPacket packet)
        {
            lock (searchLock)
            {
                foreach (var p in PvPacket.Split(packet.Data))
                {
                    var channel = p.ReadString(45);
                    searches.Add(new Search
                    {
                        Time = packet.TimeStampSeconds + "." + packet.TimeStampMicroseconds,
                        Channel = channel,
                        From = packet.Source
                    });
                }

            }
            ShowStats();
        }

        private void ShowStats()
        {
            searchScroll.Children.Clear();
            searchStatScroll.Children.Clear();
            sourceStatScroll.Children.Clear();

            lock (searchLock)
            {
                searchScroll.Children.AddRange(searches.Select(row => new RowItem { Col0 = row.Time, Col1 = row.From, Col2 = row.Channel }));
                searchStatScroll.Children.AddRange(searches.GroupBy(row => row.Channel).Select(row => new RowItem { Col0 = row.Key, Col1 = row.Count().ToString() }));
                sourceStatScroll.Children.AddRange(searches.GroupBy(row => row.From).Select(row => new RowItem { Col0 = row.Key, Col1 = row.Count().ToString() }));
            }
        }

        public void Clear()
        {
            searchScroll.Children.Clear();
            searchStatScroll.Children.Clear();
            sourceStatScroll.Children.Clear();

            lock (searchLock)
                searches.Clear();
        }
    }
}
