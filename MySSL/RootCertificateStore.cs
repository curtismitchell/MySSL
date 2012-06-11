using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    class RootCertificateStore : CertificateStoreBase
    {
        X509Store _instance;

        protected override X509Store Store
        {
            get
            {
                if (_instance == null)
                    _instance = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                return _instance;
            }
        }
    }
}
