using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    public class CertificateAuthority
    {
        readonly Authority _auth;

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
