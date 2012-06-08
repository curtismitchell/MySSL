
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
    }
}
