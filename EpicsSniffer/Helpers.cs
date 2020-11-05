using Avalonia.Controls;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EpicsSniffer
{
    public static class Helpers
    {
        public static void Resize(this Window window)
        {
            Task.Run(() =>
            {
                Thread.Sleep(100);
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    window.Width = window.Width - 1;
                });
                Thread.Sleep(100);
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    window.Width = window.Width + 1;
                });
            });
        }
    }
}
