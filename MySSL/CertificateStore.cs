using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MySSL
{
    public class CertificateStore : ICertificateStore
    {
        X509Store _xStore;
        public CertificateStore(X509Store xStore)
        {
            _xStore = xStore;
        }

        public void Save(X509Certificate2 certificate)
        {
            _xStore.Open(OpenFlags.ReadWrite);
            //_xStore.Add(certificate);
            _xStore.Certificates.Import(certificate.RawData);
            _xStore.Close();
        }

        public void Delete(X509Certificate2 certificate)
        {
            _xStore.Open(OpenFlags.ReadWrite);
            _xStore.Remove(certificate);
            _xStore.Close();
        }

        public X509Certificate2 Find(string thumbprint)
        {
            var foundCerts = _xStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            return (foundCerts.Count == 0) ? null : foundCerts[0];
        }
    }
}
