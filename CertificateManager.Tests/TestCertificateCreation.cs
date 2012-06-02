using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;

namespace CertificateManager.Tests
{
    [TestFixture]
    public class TestCertificateCreation
    {
        [Test]
        public void CreateACertificateIssuedByAGivenAuthority()
        {
            var authority = "CN=LexisNexis Practice Management Authority";
            var config = new CertificateConfiguration(authority);
            var cert = config.GenerateCertificate();
            Assert.That(cert != null);
        }
    }
}
