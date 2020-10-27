using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using System.Text;

namespace EpicsSniffer
{
    public class HexViewer : UserControl
    {
        byte[] data;
        private TextBlock txtPositions;
        private TextBlock txtHex;
        private TextBlock txtVisual;

        public byte[] Data
        {
            get
            {
                return data;
            }
            set
            {
                data = value;

                var hex = new StringBuilder();
                var chars = new StringBuilder();
                var posString = new StringBuilder();

                int nbInRow = 0;
                int pos = 0;
                foreach (var b in data)
                {
                    if (nbInRow == 0)
                        posString.Append($"{pos:X4}\n");
                    else
                        hex.Append(' ');
                    if (nbInRow == 8)
                    {
                        hex.Append("   ");
                        chars.Append("   ");
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
                        hex.Append("\n");
                        chars.Append("\n");
                    }
                }
                txtHex.Text = hex.ToString();
                txtVisual.Text = chars.ToString();
                txtPositions.Text = posString.ToString();
            }
        }

        public HexViewer()
        {
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            txtPositions = this.FindControl<TextBlock>("txtPositions");
            txtHex = this.FindControl<TextBlock>("txtHex");
            txtVisual = this.FindControl<TextBlock>("txtVisual");
        }
    }
}
