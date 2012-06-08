using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    class RootCertificateStore : CertificateStoreBase
    {
        protected override X509Store Store
        {
            get
            {
                return new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            }
        }
    }
}
