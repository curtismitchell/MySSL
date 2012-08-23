using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MySSL
{
    public class CertificateStore
    {
        private ICertificateStore _personalStore;
        private ICertificateStore _rootStore;

        public CertificateStore(ICertificateStore personalStore, ICertificateStore rootStore)
        {
            _personalStore = personalStore;
            _rootStore = rootStore;
        }

        public bool SaveAuthority(X509Certificate2 authCert)
        {
            // save cert to personalStore
            _personalStore.Save(authCert);
            // find cert in personalStore
            var savedCert = _personalStore.Find(authCert.Thumbprint);
            // save cert to authorityStore
            _rootStore.Save(savedCert);
            // remove cert from personalStore
            _personalStore.Delete(savedCert);

            return true;
        }

        public bool SaveSsl(X509Certificate2 cert)
        {
            _personalStore.Save(cert);
            return true;
        }

        public void Remove(string issuer)
        {
            var cert = _personalStore.FindByIssuer(issuer);
            _personalStore.Delete(cert);

            cert = _rootStore.FindByIssuer(issuer);
            _rootStore.Delete(cert);
        }
    }
}
