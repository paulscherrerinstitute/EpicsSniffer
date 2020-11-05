using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using ReactiveUI;

namespace EpicsSniffer
{
    public class RowItem : UserControl
    {
        public class RowItemViewModel : ReactiveObject
        {
            private string col0;
            public string Col0
            {
                get => col0;
                set => this.RaiseAndSetIfChanged(ref col0, value);
            }

            private string col1;
            public string Col1
            {
                get => col1;
                set => this.RaiseAndSetIfChanged(ref col1, value);
            }

            private string col2;
            public string Col2
            {
                get => col2;
                set => this.RaiseAndSetIfChanged(ref col2, value);
            }
        }

        public RowItemViewModel Model { get; private set; } = new RowItemViewModel { };
        private Grid rowGrid;

        public string Col0 { get => Model.Col0; set => Model.Col0 = value; }
        public string Col1 { get => Model.Col1; set => Model.Col1 = value; }
        public string Col2 { get => Model.Col2; set => Model.Col2 = value; }

        public RowItem()
        {
            this.DataContext = Model;
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            rowGrid = this.FindControl<Grid>("rowGrid");
        }
    }
}
