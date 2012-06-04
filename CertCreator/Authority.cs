using System;

namespace CertCreator
{
    public class CommonName
    {
        private readonly string _name;
        const string CommonNamePrefix = "CN=";

        public CommonName(string name)
        {
            _name = name;
        }

        /// <summary>
        /// Read-Only representation of the Common Name of the Authority.  e.g. "CN=Thawte"
        /// </summary>
        public string Name
        {
            get { return (_name.StartsWith(CommonNamePrefix, StringComparison.CurrentCultureIgnoreCase))? _name : 
                String.Concat(CommonNamePrefix, _name); }
        }
    }
}
