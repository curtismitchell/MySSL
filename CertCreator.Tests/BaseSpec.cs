using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace CertCreator.Tests
{
    [TestFixture]
    public abstract class BaseSpec
    {
        [SetUp]
        public abstract void BeforeEachSpec();
        [TearDown]
        public abstract void AfterEachSpec();
        [TestFixtureSetUp]
        public abstract void BeforeAllSpecs();
        [TestFixtureTearDown]
        public abstract void AfterAllSpecs();
    }
}
