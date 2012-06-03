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
        private Authority _authority;
        private CertificateConfiguration _config;
        private X509Certificate2 _cert;
        private DateTime _defaultExpirationDate = new DateTime(2039, 12, 31);

        [SetUp]
        public void BeforeEachTest()
        {
            _authority = new Authority("LexisNexis Practice Management Authority");
            _config = new CertificateConfiguration(_authority);
        }

        [Test]
        public void CreateACertificateIssuedByAGivenAuthority()
        {
            _cert = _config.GenerateCertificate();
            Assert.That(_cert != null);
        }

        [Test]
        public void DefaultCertificateConfigurationShouldUseTodayAsTheEffectiveDate()
        {
            Assert.That(_config.EffectiveDate == DateTime.Today);
        }

        [Test]
        public void DefaultCertificateConfigurationShouldHaveADefaultExpirationDateOf2039()
        {
            Assert.That(_config.ExpirationDate == _defaultExpirationDate);
        }

        [Test]
        public void CertificateConfigurationShouldThrowIfEffectiveDateIsAfterExpirationDate()
        {
            Assert.Throws<InvalidOperationException>(() =>
                {
                    _config.ExpirationDate = DateTime.Today.AddDays(1);
                    _config.EffectiveDate = DateTime.Today.AddDays(2);
                });
        }

        [Test]
        public void ShouldBeAbleToChangeTheSerialNumberOfTheCertificate()
        {
            _cert = _config.GenerateCertificate();
            _config.SerialNumber = 2;
            var cert2 = _config.GenerateCertificate();
            Assert.That(_cert.GetSerialNumberString() != cert2.GetSerialNumberString());
        }

        [Test]
        public void ShouldBeAbleToChangeTheExpirationDate()
        {
            _config.ExpirationDate = new DateTime(2035, 12, 31);
            var cert2 = _config.GenerateCertificate();
            Assert.That(cert2.NotAfter.Year == 2035);
        }


    }
}
