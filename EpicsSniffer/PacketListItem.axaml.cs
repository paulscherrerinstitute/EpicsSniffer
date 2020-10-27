using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using PCapReader;
using ReactiveUI;

namespace EpicsSniffer
{
    public class PacketListItem : UserControl
    {
        public class PacketListItemViewModel : ReactiveObject
        {
            private int packetNumber;
            public int PacketNumber
            {
                get => packetNumber;
                set => this.RaiseAndSetIfChanged(ref packetNumber, value);
            }

            private string packetSource;
            public string PacketSource
            {
                get => packetSource;
                set => this.RaiseAndSetIfChanged(ref packetSource, value);
            }

            private string packetDestination;
            public string PacketDestination
            {
                get => packetDestination;
                set => this.RaiseAndSetIfChanged(ref packetDestination, value);
            }

            private string packetProtocol;
            public string PacketProtocol
            {
                get => packetProtocol;
                set => this.RaiseAndSetIfChanged(ref packetProtocol, value);
            }

            private int packetLength;
            public int PacketLength
            {
                get => packetLength;
                set => this.RaiseAndSetIfChanged(ref packetLength, value);
            }
        }

        public PacketListItemViewModel Model { get; private set; } = new PacketListItemViewModel { };
        bool selected = false;
        private Grid rowGrid;

        public bool Selected
        {
            get
            {
                return selected;
            }
            set
            {
                selected = value;
                rowGrid.Background = (Selected ? new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0xE0, 0xE0)) : Brushes.White);
            }
        }

        public int PacketNumber
        {
            get
            {
                return Model.PacketNumber;
            }
            set
            {
                Model.PacketNumber = value;
            }
        }

        public string PacketSource
        {
            get
            {
                return Model.PacketSource;
            }
            set
            {
                Model.PacketSource = value;
            }
        }

        public string PacketDestination
        {
            get
            {
                return Model.PacketDestination;
            }
            set
            {
                Model.PacketDestination = value;
            }
        }

        public string PacketProtocol
        {
            get
            {
                return Model.PacketProtocol;
            }
            set
            {
                Model.PacketProtocol = value;
            }
        }

        public int PacketLength
        {
            get
            {
                return Model.PacketLength;
            }
            set
            {
                Model.PacketLength = value;
            }
        }

        public PCapPacket Packet { get; internal set; }

        public PacketListItem()
        {
            this.DataContext = Model;
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            rowGrid = this.FindControl<Grid>("rowGrid");
        }

        public delegate void ClickEventDelegate(object sender, RoutedEventArgs e);
        public event ClickEventDelegate Click;

        private void RowClick_Event(object sender, RoutedEventArgs e)
        {
            Click?.Invoke(this, e);
        }
    }
}
