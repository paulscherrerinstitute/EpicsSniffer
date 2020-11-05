using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace EpicsSniffer
{
    public class AdminRightsRequired : Window
    {
        public AdminRightsRequired()
        {
            this.InitializeComponent();
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void BtnCloseClick(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            this.Close(null);
        }


        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            this.Resize();
        }
    }
}
