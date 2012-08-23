using NUnit.Framework;
using Moq;

namespace MySSL.Tests
{
    [TestFixture]
    public class CertificateStoreTests
    {
        Mock<ICertificateStore> _mockPersonalStore = new Mock<ICertificateStore>();
        Mock<ICertificateStore> _mockRootStore = new Mock<ICertificateStore>();
        CertificateStore _certStore;
        CertificateAuthority _authority;

        [SetUp]
        public void BeforeEachTest()
        {
            _authority = new CertificateAuthority("MyAuthority");
            _mockPersonalStore = new Mock<ICertificateStore>();
            _mockRootStore = new Mock<ICertificateStore>();
            _certStore = new CertificateStore(_mockPersonalStore.Object, _mockRootStore.Object);
        }

        [Test]
        public void ShouldSaveTheAuthorityCertificate()
        {
            var cert = _authority.ToX509Certificate();
            _mockPersonalStore.Setup(x => x.Find(cert.Thumbprint)).Returns(cert);

            var certStore = new CertificateStore(_mockPersonalStore.Object, _mockRootStore.Object);
            Assert.That(certStore.SaveAuthority(cert));

            _mockPersonalStore.Verify(x => x.Save(cert)); //saved to personalStore first
            _mockRootStore.Verify(x => x.Save(cert)); //saved to rootStore 
            _mockPersonalStore.Verify(x => x.Delete(cert)); //removed from personalStore
        }

        [Test]
        public void ShouldSaveTheSslCertificate()
        {
            var cert = _authority.CreateSsl();
            Assert.That(_certStore.SaveSsl(cert));
            _mockPersonalStore.Verify(x => x.Save(cert));
        }

        [Test]
        public void ShouldRemoveAuthorityAndRelatedCertificates()
        {
            var cert = _authority.CreateSsl();
            var authCert = _authority.ToX509Certificate();
            _mockPersonalStore.Setup(x => x.FindByIssuer("MyAuthority")).Returns(cert);
            _mockRootStore.Setup(x => x.FindByIssuer("MyAuthority")).Returns(authCert);

            _certStore.Remove("MyAuthority");

            _mockPersonalStore.Verify(x => x.FindByIssuer("MyAuthority"));
            _mockPersonalStore.Verify(x => x.Delete(cert));

            _mockRootStore.Verify(x => x.FindByIssuer("MyAuthority"));
            _mockRootStore.Verify(x => x.Delete(authCert));
        }
    }
}
