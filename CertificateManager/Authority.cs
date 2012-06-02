using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CertificateManager
{
    public class Authority
    {
        private string name;
        const string CommonNamePrefix = "CN=";

        public Authority(string name)
        {
            this.name = name;
        }

        public string CommonName
        {
            get { return (name.StartsWith(CommonNamePrefix))? name : 
                String.Concat(CommonNamePrefix, name); }
        }
    }
}
