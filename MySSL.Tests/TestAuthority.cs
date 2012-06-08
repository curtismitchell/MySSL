using System;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestAuthority
    {
        Authority _auth;
        X509Certificate2 _sslCert;

        [SetUp]
        public void BeforeEachTest()
        {
            _auth = new Authority("TestAuthority");
            _sslCert = _auth.GetSSLCertificate();
        }

        [Test]
        public void IssuerShouldBeTheSameAsTheSubject()
        {
            Assert.That(_auth.X509Certificate.Subject == _auth.X509Certificate.Issuer);
        }

        [Test]
        public void AuthorityCertificateMustHavetheAuthorityKeyIdentifierExtension()
        {
            var aki = GetAuthorityKeyIdentifierText(_auth.X509Certificate);
            Assert.That(aki != String.Empty);
        }

        [Test]
        public void AuthorityCertificateMustHaveABasicConstraintExtensionOfCA()
        {
            var hasExtension = false;
            foreach (var ext in _auth.X509Certificate.Extensions)
            {
                if (ext.Format(true).StartsWith("Subject Type=CA"))
                {
                    hasExtension = true;
                    break;
                }
            }

            Assert.That(hasExtension);
        }

        [Test]
        public void AuthorityShouldIssueSSLCertificates()
        {
            Assert.That(_sslCert != null);
        }

        [Test]
        public void SSLCertificateShouldHaveIssuerThatMatchesAuthority()
        {
            Assert.That(_sslCert.Issuer == _auth.X509Certificate.Subject);
        }

        [Test]
        public void SSLCertificateShouldHaveMachineNameAsSubject()
        {
            var machineName = Environment.MachineName;
            Assert.That(machineName == _sslCert.Subject.Replace("CN=", ""), String.Format("The machine is named {0}, and the subject of the cert is {1}", machineName, _sslCert.Subject));
        }

        [Test]
        public void SSLCertificateShouldHaveAuthorityKeyIdentifierExtension()
        {
            var aki = GetAuthorityKeyIdentifierText(_sslCert);
            Assert.That(aki != String.Empty);
        }

        [Test]
        public void SSLCertificateAuthorityKeyIdentifierExtensionShouldContainAuthoritySerialNumber()
        {
            var aki = GetAuthorityKeyIdentifierText(_sslCert);
            var serial = _auth.X509Certificate.SerialNumber;
            Assert.That(aki.Replace(" ",String.Empty).ToUpper().Contains(serial),
                String.Format("{0} does not contain {1}", aki, serial));
        }

        private string GetAuthorityKeyIdentifierText(X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Format(true).StartsWith("KeyID"))
                {
                    return ext.Format(true);
                }
            }

            return String.Empty;
        }

        [Test]
        public void SSLCertificateRequiresExtendedKeyUsageForServerAuthentication()
        {
            var hasServerAuthentication = false;

            foreach (var ext in _sslCert.Extensions)
            {
                if (ext.Format(true).StartsWith("Server Authentication"))
                {
                    hasServerAuthentication = true;
                    break;
                }
            }

            Assert.That(hasServerAuthentication);
        }

        [Test]
        public void SSLCertificateShouldHaveMatchingPublicKeyAsAuthority()
        {
            Assert.That(_auth.X509Certificate.PublicKey.EncodedKeyValue.Format(false) == _sslCert.PublicKey.EncodedKeyValue.Format(false));
        }

        [Test]
        public void SSLCertificateShouldHaveBasicConstraintsNotCA()
        {
            var hasExtension = false;
            foreach (var ext in _sslCert.Extensions)
            {
                if (ext.Format(true).StartsWith("Subject Type=End Entity"))
                {
                    hasExtension = true;
                    break;
                }
            }

            Assert.That(hasExtension);
        }

        [Test]
        public void SSLCertificateShouldHaveASetPrivateKey()
        {
            Assert.That(_sslCert.HasPrivateKey);
            
        }
    }
}
