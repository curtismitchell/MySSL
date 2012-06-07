using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace MySSL.Tests
{
    [TestFixture]
    public class TestCommonName
    {
        [Test]
        public void NameShouldHavePrependedQualifier()
        {
            var auth = new CommonName("Curtis Mitchell");
            Assert.That(auth.Name.Equals("CN=Curtis Mitchell"));
        }

        [Test]
        public void NameShouldOnlyAppendTheCommonNameQualifierIfNecessary()
        {
            var auth = new CommonName("CN=Curtis Mitchell");
            Assert.That(auth.Name.Equals("CN=Curtis Mitchell"));
        }
    }
}
