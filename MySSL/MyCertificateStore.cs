using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    class MyCertificateStore : CertificateStoreBase
    {
        protected override X509Store Store
        {
            get { return new X509Store(StoreName.My, StoreLocation.LocalMachine); }
        }
    }
}
