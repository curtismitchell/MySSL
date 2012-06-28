using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MySSL
{
    public class CertificateNotFoundException : Exception
    {
        public CertificateNotFoundException() : base("The certificate was not found.")
        {

        }
    }
}
