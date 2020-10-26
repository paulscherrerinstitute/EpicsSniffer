using System;
using System.Collections.Generic;
using System.Text;

namespace PCapReader
{
    public class FileFormatException : Exception
    {
        public FileFormatException(string message) : base(message)
        {
        }
    }
}
