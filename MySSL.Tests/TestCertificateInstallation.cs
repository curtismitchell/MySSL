using System.Security.Cryptography.X509Certificates;
using Moq;
using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestCertificateInstallation
    {
        Mock<ICertificateStore> _mockPersonalStore;
        Mock<ICertificateStore> _mockRootStore;
        CertificateInstallation _certInstall;
        Mock<Authority> _authCert;

        [SetUp]
        public void BeforeEachTest()
        {
            _mockPersonalStore = new Mock<ICertificateStore>();
            _mockRootStore = new Mock<ICertificateStore>();
            _certInstall = new CertificateInstallation(_mockPersonalStore.Object, _mockRootStore.Object);
            _authCert = new Mock<Authority>("TestAuthority");
        }

        [Test]
        public void CertificateInstallationShouldSaveAuthorityToTrustedRoot()
        {
            _certInstall.InstallAuthority(_authCert.Object.X509Certificate);
            _mockPersonalStore.Verify(_ => _.Save(It.IsAny<X509Certificate2>()));
            _mockRootStore.Verify(_ => _.Save(It.IsAny<X509Certificate2>()));
            _mockPersonalStore.Verify(_ => _.Delete(It.IsAny<X509Certificate2>()));
        }

        [Test]
        public void CertificateInstallationShouldSaveSSLCertificateToPersonalStore()
        {
            var cert = new X509Certificate2();

            _certInstall.InstallSSL(cert);

            _mockPersonalStore.Verify(_ => _.Save(cert));
        }
    }
}
