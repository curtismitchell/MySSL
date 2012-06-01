using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CertificateManager
{
    public class CertificateManager
    {
        const string SignatureAlgorithm = "SHA1WithRSAEncryption";
        const int BytesInKeyStrength = 2048;

        /// <summary>
        /// Creates a certficate that is trusted by the specified authority
        /// </summary>
        /// <param name="authority">Name of the authority that approves the certificate</param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 Create(string authority)
        {
            var keys = CreateKeyPair(BytesInKeyStrength);

            var certGen = new X509V3CertificateGenerator();
            var dnName = new X509Name(authority);

            certGen.SetSerialNumber(BigInteger.ValueOf(1));
            certGen.SetIssuerDN(dnName);
            certGen.SetNotBefore(DateTime.Today);
            certGen.SetNotAfter(DateTime.Today.AddYears(10));
            certGen.SetSubjectDN(dnName);
            certGen.SetPublicKey(keys.Public);
            certGen.SetSignatureAlgorithm(SignatureAlgorithm);

            return new X509Certificate2(certGen.Generate(keys.Private).GetEncoded());
        }

        /// <summary>
        /// Creates a keypair
        /// </summary>
        /// <param name="strength">integer representing the number of bits</param>
        /// <returns>AsymmetricCipherKeyPair</returns>
        private static AsymmetricCipherKeyPair CreateKeyPair(int strength)
        {
            var keygen = new RsaKeyPairGenerator();
            keygen.Init(new KeyGenerationParameters(new SecureRandom(), strength));
            var keys = keygen.GenerateKeyPair();
            return keys;
        }

        private BigInteger GenerateRandomSerialNumber()
        {
            var rand = new Random();
            return BigInteger.ValueOf(rand.Next());            
        }
    }
}
