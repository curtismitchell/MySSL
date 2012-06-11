using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    class MyCertificateStore : CertificateStoreBase
    {
        // need to make sure this does not return a new instance each time.
        // also, create integration tests for this project
        private X509Store _instance;

        protected override X509Store Store
        {
            get
            {
                if (_instance == null)
                    _instance = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                return _instance;
            }
        }
    }
}
