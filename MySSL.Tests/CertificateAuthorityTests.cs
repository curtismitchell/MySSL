using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class CertificateAuthorityTests
    {
        [Test]
        public void ShouldCreateAnX509Certificate()
        {
            var auth = new CertificateAuthority("MyAuthority");
            var cert = auth.ToX509Certificate();
            Assert.That(cert != null);
        }

        [Test]
        public void ShouldCreateAnSslCertificate()
        {
            var auth = new CertificateAuthority("MyAuthority");
            var cert = auth.CreateSsl();
            Assert.That(cert != null);
        }
    }
}
