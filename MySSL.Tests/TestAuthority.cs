using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestAuthority
    {
        [Test]
        public void AuthorityShouldCreateAProperCommonName()
        {
            var auth = new CommonName("Curtis Mitchell");
            Assert.That(auth.Name.Equals("CN=Curtis Mitchell"));
        }

        [Test]
        public void AuthorityShouldOnlyAppendTheCommonNameQualifierIfNecessary()
        {
            var auth = new CommonName("CN=Curtis Mitchell");
            Assert.That(auth.Name.Equals("CN=Curtis Mitchell"));
        }
    }
}
