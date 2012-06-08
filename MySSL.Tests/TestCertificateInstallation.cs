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

        [Test]
        public void CertificateInstallationShouldInstallBothCertificates()
        {
            var ca = new Authority("TestAuthority");
            var sslCert = ca.GetSSLCertificate();
            _mockPersonalStore.Setup(_ => _.Find(ca.X509Certificate.Thumbprint))
                .Returns(ca.X509Certificate);

            _certInstall.Install(ca.X509Certificate, sslCert);

            _mockPersonalStore.Verify(_ => _.Save(ca.X509Certificate));
            _mockRootStore.Verify(_ => _.Save(ca.X509Certificate));
            _mockPersonalStore.Verify(_ => _.Delete(ca.X509Certificate));

            _mockPersonalStore.Verify(_ => _.Save(sslCert));
        }
    }
}
