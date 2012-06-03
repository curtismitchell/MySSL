using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace CertCreator.Tests
{
    [TestFixture]
    public class TestAuthority
    {
        [Test]
        public void AuthorityShouldCreateAProperCommonName()
        {
            var auth = new Authority("Curtis Mitchell");
            Assert.That(auth.CommonName.Equals("CN=Curtis Mitchell"));
        }

        [Test]
        public void AuthorityShouldOnlyAppendTheCommonNameQualifierIfNecessary()
        {
            var auth = new Authority("CN=Curtis Mitchell");
            Assert.That(auth.CommonName.Equals("CN=Curtis Mitchell"));
        }
    }
}
