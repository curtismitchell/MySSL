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

namespace CertCreator
{
    public class CertificateConfiguration
    {
        const string SignatureAlgorithm = "SHA1WithRSAEncryption";
        const int BytesInKeyStrength = 2048;
        const int DefaultSerialNumber = 1;

        private readonly DateTime DefaultExpirationDate = new DateTime(2039, 12, 31);
        private readonly CommonName _authority;
        private DateTime _effectiveDate = DateTime.Today;

        public CertificateConfiguration(CommonName authority)
        {
            _authority = authority;
            ExpirationDate = DefaultExpirationDate;
            SerialNumber = DefaultSerialNumber;
            Subject = authority;
        }

        /// <summary>
        /// Creates a trusted certficate
        /// </summary>
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 GenerateCertificate()
        {
            var keys = CreateKeyPair();

            var certGen = new X509V3CertificateGenerator();
            var dnName = new X509Name(_authority.Name);
            var subjectName = new X509Name(Subject.Name);

            certGen.SetSerialNumber(BigInteger.ValueOf(SerialNumber));
            certGen.SetIssuerDN(dnName);
            certGen.SetNotBefore(EffectiveDate);
            certGen.SetNotAfter(ExpirationDate);
            certGen.SetSubjectDN(subjectName);
            certGen.SetPublicKey(keys.Public);
            certGen.SetSignatureAlgorithm(SignatureAlgorithm);

            return new X509Certificate2(certGen.Generate(keys.Private).GetEncoded());
        }

        /// <summary>
        /// Creates a keypair
        /// </summary>
        /// <returns>AsymmetricCipherKeyPair</returns>
        private AsymmetricCipherKeyPair CreateKeyPair()
        {
            var keygen = new RsaKeyPairGenerator();
            keygen.Init(new KeyGenerationParameters(new SecureRandom(), BytesInKeyStrength));
            var keys = keygen.GenerateKeyPair();
            return keys;
        }

        public DateTime EffectiveDate {
            get { return this._effectiveDate; }
            set
            {
                if (value > ExpirationDate)
                    throw new InvalidOperationException("The EffectiveDate cannot be after the ExpirationDate");

                this._effectiveDate = value;
            }
        }

        public DateTime ExpirationDate { get; set; }

        public int SerialNumber { get; set; }

        public CommonName Subject { get; set; }
    }
}
