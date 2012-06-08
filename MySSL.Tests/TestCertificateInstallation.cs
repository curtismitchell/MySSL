using System.Security.Cryptography.X509Certificates;
using Moq;
using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestCertificateInstallation
    {
        [Test]
        public void CertificateInstallationShouldSaveAuthorityToTrustedRoot()
        {
            var mockPersonalStore = new Mock<ICertificateStore>();
            var mockRootStore = new Mock<ICertificateStore>();
            var certInstall = new CertificateInstallation(mockPersonalStore.Object, mockRootStore.Object);
            var authCert = new Mock<Authority>("TestAuthority");

            certInstall.InstallAuthority(authCert.Object.X509Certificate);
            mockPersonalStore.Verify(_ => _.Save(It.IsAny<X509Certificate2>()));
            mockRootStore.Verify(_ => _.Save(It.IsAny<X509Certificate2>()));
            mockPersonalStore.Verify(_ => _.Delete(It.IsAny<X509Certificate2>()));
        }
    }
}
