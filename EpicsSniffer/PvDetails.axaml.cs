using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using ReactiveUI;

namespace EpicsSniffer
{
    public class PvDetails : UserControl
    {
        public class PvDetailsViewModel : ReactiveObject
        {
            private string source;
            public string Source
            {
                get => source;
                set => this.RaiseAndSetIfChanged(ref source, value);
            }

            private string destination;
            public string Destination
            {
                get => destination;
                set => this.RaiseAndSetIfChanged(ref destination, value);
            }

            private string command;
            public string Command
            {
                get => command;
                set => this.RaiseAndSetIfChanged(ref command, value);
            }

            private string flags;
            public string Flags
            {
                get => flags;
                set => this.RaiseAndSetIfChanged(ref flags, value);
            }

            private int payloadSize;
            public int PayloadSize
            {
                get => payloadSize;
                set => this.RaiseAndSetIfChanged(ref payloadSize, value);
            }
        }

        public string Source
        {
            get => Model.Source;
            set => Model.Source = value;
        }

        public string Destination
        {
            get => Model.Destination;
            set => Model.Destination = value;
        }

        public string Command
        {
            get => Model.Command;
            set => Model.Command = value;
        }

        public string Flags
        {
            get => Model.Flags;
            set => Model.Flags = value;
        }

        public int PayloadSize
        {
            get => Model.PayloadSize;
            set => Model.PayloadSize = value;
        }

        private PvDetailsViewModel Model = new PvDetailsViewModel();

        public PvDetails()
        {
            this.InitializeComponent();
            this.DataContext = Model;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}
