using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MySSL
{
    abstract class CertificateStoreBase : ICertificateStore
    {
        protected abstract X509Store Store { get; }

        public virtual void Save(X509Certificate2 certificate)
        {
            Store.Open(OpenFlags.ReadWrite);
            Store.Add(certificate);
            Store.Close();
        }

        public virtual void Delete(X509Certificate2 certificate)
        {
            Store.Open(OpenFlags.ReadWrite);
            Store.Remove(certificate);
            Store.Close();
        }

        public virtual X509Certificate2 Find(string thumbprint)
        {
            Store.Open(OpenFlags.ReadOnly);
            var foundCerts = Store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            Store.Close();
            return (foundCerts.Count == 0) ? null : foundCerts[0];
        }

        public virtual X509Certificate2 FindByIssuer(string issuer)
        {
            Store.Open(OpenFlags.ReadOnly);
            var foundCerts = Store.Certificates.Find(X509FindType.FindByIssuerName, issuer, false);
            Store.Close();
            return (foundCerts.Count == 0) ? null : foundCerts[0];
        }
    }
}
