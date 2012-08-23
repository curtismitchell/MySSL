using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Moq;

namespace MySSL.Tests
{
    [TestFixture]
    public class CertificateStoreTests
    {
        [Test]
        public void ShouldSaveTheAuthorityCertificate()
        {
            var auth = new CertificateAuthority("MyAuthority");
            var mockPersonalStore = new Mock<ICertificateStore>();
            var mockRootStore = new Mock<ICertificateStore>();
            var cert = auth.ToX509Certificate();
            mockPersonalStore.Setup(x => x.Find(cert.Thumbprint)).Returns(cert);

            var certStore = new CertificateStore(mockPersonalStore.Object, mockRootStore.Object);
            Assert.That(certStore.SaveAuthority(cert));

            mockPersonalStore.Verify(x => x.Save(cert)); //saved to personalStore first
            mockRootStore.Verify(x => x.Save(cert)); //saved to rootStore 
            mockPersonalStore.Verify(x => x.Delete(cert)); //removed from personalStore
        }

        [Test]
        public void ShouldSaveTheSSLCertificate()
        {
            var auth = new CertificateAuthority("MyAuthority");
            var mockPersonalStore = new Mock<ICertificateStore>();
            var mockRootStore = new Mock<ICertificateStore>();
            var cert = auth.CreateSsl();

            var certStore = new CertificateStore(mockPersonalStore.Object, mockRootStore.Object);
            Assert.That(certStore.SaveSsl(cert));
            mockPersonalStore.Verify(x => x.Save(cert));
        }
    }
}
