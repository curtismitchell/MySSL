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

        [TearDown]
        public void AfterEachTest()
        {
            _mockPersonalStore = null;
            _mockRootStore = null;
            _certInstall = null;
            _authCert = null;
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

        [Test]
        public void CertificateInstallationShouldRemoveSSLIfFound()
        {
            var ca = new Authority("TestAuthority");
            var sslCert = ca.GetSSLCertificate();
            _mockPersonalStore.Setup(_ => _.Find(sslCert.Thumbprint))
                .Returns(sslCert);

            _certInstall.UninstallSSL(sslCert.Thumbprint);
            _mockPersonalStore.Verify(_ => _.Find(sslCert.Thumbprint));
            _mockPersonalStore.Verify(_ => _.Delete(sslCert));
        }

        [Test]
        public void ShouldThrowIfSSLCertificateIsNotFoundAndCannotBeRemoved()
        {
            var ca = new Authority("TestAuthority");
            var sslCert = ca.GetSSLCertificate();
            _mockPersonalStore.Setup(_ => _.Find(sslCert.Thumbprint))
                .Returns<X509Certificate2>(null);

            Assert.Throws<CertificateNotFoundException>(() =>
                _certInstall.UninstallSSL(sslCert.Thumbprint)
                );
        }

        [Test]
        public void ShouldRemoveAuthorityIfFound()
        {
            var ca = new Authority("TestAuthority");

            _mockRootStore.Setup(_ => _.Find(ca.X509Certificate.Thumbprint))
                .Returns(ca.X509Certificate);

            _certInstall.UninstallAuthority(ca.X509Certificate.Thumbprint);
            _mockRootStore.Verify(_ => _.Find(ca.X509Certificate.Thumbprint));
            _mockRootStore.Verify(_ => _.Delete(ca.X509Certificate));
        }

        [Test]
        public void ShouldThrowIfAuthorityIsNotFound()
        {
            var ca = new Authority("TestAuthority");
  
            _mockRootStore.Setup(_ => _.Find(ca.X509Certificate.Thumbprint))
                .Returns<X509Certificate>(null);

            Assert.Throws<CertificateNotFoundException>(() =>
                _certInstall.UninstallAuthority(ca.X509Certificate.Thumbprint)
                );
        }
    }
}
