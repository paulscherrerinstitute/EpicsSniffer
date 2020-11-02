using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using System.Linq;
using System.Net.NetworkInformation;

namespace EpicsSniffer
{
    public class CaptureWindow : Window
    {
        private ComboBox networkList;

        public CaptureWindow()
        {
            this.InitializeComponent();
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);

            networkList = this.FindControl<ComboBox>("networkList");
            networkList.Items = NetworkInterface.GetAllNetworkInterfaces()
                .Where(row => row.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .OrderBy(row => row.Name)
                .Select(row => row.Name + " (" + row.GetIPProperties().UnicastAddresses.First().Address.MapToIPv4().ToString() + ")");
            networkList.SelectedIndex = 0;
        }

        private void BtnCaptureClick(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            this.Close(((string)networkList.SelectedItem).Split(" (").Last().Split(")").First());
        }

        private void BtnCancelClick(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            this.Close(null);
        }
    }
}
