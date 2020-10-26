using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
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

        public PacketListItem()
        {
            this.DataContext = Model;
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}
