using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MySSL
{
    public class CertificateAuthority
    {
        Authority _auth;
        public CertificateAuthority(string name)
        {
            _auth = new Authority(name);
        }

        public X509Certificate2 ToX509Certificate()
        {
            return _auth.X509Certificate;
        }

        public X509Certificate2 CreateSsl()
        {
            return _auth.GetSSLCertificate();
        }
    }
}
