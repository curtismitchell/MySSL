using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;

namespace CertificateManager.Tests
{
    public class TestCertificateCreation : BaseSpec
    {

        [Test]
        public void CreateACertificateIssuedByAGivenAuthority()
        {
            var authority = "CN=LexisNexis Practice Management Authority";
            var cert = CertificateManager.Create(authority);
            Assert.That(cert != null);
        }

        [Test]
        public void ShouldThrowAnExceptionIfAuthorityNameIsInvalid()
        {
            var authority = "LexisNexis Practice Management Authority";
            Assert.Throws<ArgumentException>(() =>
            {
                var cert = CertificateManager.Create(authority);
            });
        }

        public override void BeforeEachSpec()
        {

        }

        public override void AfterEachSpec()
        {

        }

        public override void BeforeAllSpecs()
        {

        }

        public override void AfterAllSpecs()
        {

        }
    }
}
