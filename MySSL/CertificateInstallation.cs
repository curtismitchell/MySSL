using System.Security.Cryptography.X509Certificates;

namespace MySSL
{
    public class CertificateInstallation
    {
        ICertificateStore _personalStore;
        ICertificateStore _authorityStore;

        public CertificateInstallation(ICertificateStore personalStore, ICertificateStore authorityStore)
        {
            _personalStore = personalStore;
            _authorityStore = authorityStore;
        }

        /// <summary>
        /// Uses the Root store for the authority certificate and My store for the ssl certificate
        /// </summary>
        public CertificateInstallation() :
            this(new MyCertificateStore(), new RootCertificateStore())
        {
            
        }

        public void InstallAuthority(X509Certificate2 authCert)
        {
            // save cert to personalStore
            _personalStore.Save(authCert);
            // find cert in personalStore
            var savedCert = _personalStore.Find(authCert.Thumbprint);
            // save cert to authorityStore
            _authorityStore.Save(savedCert);
            // remove cert from personalStore
            _personalStore.Delete(savedCert);
        }

        public void InstallSSL(X509Certificate2 sslCertificate)
        {
            _personalStore.Save(sslCertificate);
        }

        public void Install(X509Certificate2 authorityCertificate, X509Certificate2 sslCertificate)
        {
            InstallAuthority(authorityCertificate);
            InstallSSL(sslCertificate);
        }
    }
}
