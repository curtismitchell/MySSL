using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
            Assert.That(cert is X509Certificate2);
        }

        [Test]
        public void ShouldCreateAnSSLCertificate()
        {
            var auth = new CertificateAuthority("MyAuthority");
            var cert = auth.CreateSsl();
            Assert.That(cert is X509Certificate2);
        }
    }
}
