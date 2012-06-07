using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestAuthority
    {

        [Test]
        public void IssuerShouldBeTheSameAsTheSubject()
        {
            var auth = new Authority("TestAuthority");
            Assert.That(auth.X509Certificate.Subject == auth.X509Certificate.Issuer);
        }

        [Test]
        public void AuthorityCertificateMustHavetheAuthorityKeyIdentifierExtension()
        {
            var auth = new Authority("TestAuthority");
            var hasExtension = false;
            foreach (var ext in auth.X509Certificate.Extensions)
            {
                if (ext.Format(true).StartsWith("KeyID"))
                {
                    hasExtension = true;
                    break;
                }
            }

            Assert.That(hasExtension);
        }
    }
}
