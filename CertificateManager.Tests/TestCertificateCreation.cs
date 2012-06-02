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
        private Authority authority;
        private CertificateConfiguration config;
        private X509Certificate2 cert;

        [SetUp]
        public void BeforeEachTest()
        {
            authority = new Authority("LexisNexis Practice Management Authority");
            config = new CertificateConfiguration(authority);
        }

        [Test]
        public void CreateACertificateIssuedByAGivenAuthority()
        {
            cert = config.GenerateCertificate();
            Assert.That(cert != null);
        }

        [Test]
        public void DefaultCertificateConfigurationShouldUseTodayAsTheEffectiveDate()
        {
            Assert.That(config.EffectiveDate == DateTime.Today);
        }

        [Test]
        public void DefaultCertificateConfigurationShouldHaveADefaultExpirationDateOf2039()
        {
            Assert.That(config.ExpirationDate == new DateTime(2039, 12, 31));
        }

        [Test]
        public void CertificateConfigurationShouldThrowIfEffectiveDateIsAfterExpirationDate()
        {
            Assert.Throws<InvalidOperationException>(() =>
                {
                    config.ExpirationDate = DateTime.Today.AddDays(1);
                    config.EffectiveDate = DateTime.Today.AddDays(2);
                });
        }
    }
}
