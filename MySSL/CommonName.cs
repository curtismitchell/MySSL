using System;

namespace MySSL
{
    /// <summary>
    /// Handles the formatting of directory strings.  e.g. LexisNexis gets formatted as CN=LexisNexis
    /// </summary>
    public class CommonName
    {
        private readonly string _name;
        const string CommonNamePrefix = "CN=";

        public CommonName(string name)
        {
            _name = name;
        }

        /// <summary>
        /// Read-Only representation of  a Common Name.  e.g. "CN=Thawte"
        /// </summary>
        public string Name
        {
            get { return (_name.StartsWith(CommonNamePrefix, StringComparison.CurrentCultureIgnoreCase))? _name : 
                String.Concat(CommonNamePrefix, _name); }
        }
    }
}
