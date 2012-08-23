
using System.Security.Cryptography.X509Certificates;
namespace MySSL
{
    public interface ICertificateStore
    {
        void Save(X509Certificate2 certificate);
        void Delete(X509Certificate2 certificate);
        X509Certificate2 Find(string thumbprint);
        X509Certificate2 FindByIssuer(string issuer);
    }
}
