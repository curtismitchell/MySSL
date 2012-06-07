using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace MySSL
{
    public class CertificateConfiguration
    {
        const string SignatureAlgorithm = "SHA1WithRSAEncryption";
        const int BytesInKeyStrength = 1024;
        const int DefaultSerialNumber = 1;
        const string StrongPassword = @"AAAAB3NzaC1yc2EAAAABJQAAAIEAioM3Ov1Nr5ZFac6ItZj4wnzVdhKwp7HQF/T/cFSjuaZjlU89ndDqs5/9TSF5m+0EI441ocK5gw4hAGwTg7ysO2P56mBSFsHTtYWXxee8MU3YEi47Y5pruklIg7JJsHZ6GLRFZuzeIITBI7HulNS1LDjuFjvxcu9HVEYedrPRBLU=";

        private readonly DateTime DefaultExpirationDate = new DateTime(2039, 12, 31);
        private readonly CommonName _authority;
        private DateTime _effectiveDate = DateTime.Today;
        private AsymmetricCipherKeyPair _keyPair;
        private BigInteger _authSerial;

        public CertificateConfiguration(CommonName authority)
        {
            _authority = authority;
            _keyPair = CreateKeyPair();
            ExpirationDate = DefaultExpirationDate;
            SerialNumber = DefaultSerialNumber;
            Subject = authority;
            _authSerial = BigInteger.ProbablePrime(120, new Random());
        }

        /// <summary>
        /// Creates a trusted certficate
        /// </summary>
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 GenerateCertificate()
        {
            var certGen = new X509V3CertificateGenerator();
            var dnName = new X509Name(_authority.Name);
            var subjectName = new X509Name(Subject.Name);

            certGen.SetSerialNumber(_authSerial);
            certGen.SetIssuerDN(dnName);
            certGen.SetNotBefore(EffectiveDate);
            certGen.SetNotAfter(ExpirationDate);
            certGen.SetSubjectDN(subjectName);
            certGen.SetPublicKey(_keyPair.Public);
            certGen.SetSignatureAlgorithm(SignatureAlgorithm);

            //certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            //        new SubjectKeyIdentifierStructure(_keyPair.Public));

            certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier.Id,
                false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public),
                    new GeneralNames(new GeneralName(dnName)), _authSerial));

            //certGen.AddExtension(
            //    X509Extensions.KeyUsage,
            //    true,
            //    new KeyUsage(KeyUsage.KeyCertSign));

            certGen.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(true).ToAsn1Object());

            var cert = certGen.Generate(_keyPair.Private);
            var dotnetcert = new X509Certificate2(DotNetUtilities.ToX509Certificate((Org.BouncyCastle.X509.X509Certificate)cert));
            //var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)_keyPair.Private);
            //var rsa = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)_keyPair.Private);
            //dotnetcert.PrivateKey = rsa;
            return dotnetcert;
        }

        /// <summary>
        /// Creates a trusted certficate
        /// </summary>
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 GetSSLCertificate()
        {
            var serial = BigInteger.ProbablePrime(120, new Random());
            var certGen = new X509V3CertificateGenerator();
            var dnName = new X509Name(_authority.Name);
            var subjectName = new X509Name(Subject.Name);
            
            certGen.SetSerialNumber(serial);
            certGen.SetIssuerDN(dnName);
            certGen.SetNotBefore(EffectiveDate);
            certGen.SetNotAfter(ExpirationDate);
            certGen.SetSubjectDN(subjectName);
            certGen.SetSignatureAlgorithm(SignatureAlgorithm);
            certGen.SetPublicKey(_keyPair.Public);

            certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public),
                    new GeneralNames(new GeneralName(dnName)), _authSerial));

            certGen.AddExtension(
                X509Extensions.ExtendedKeyUsage.Id,
                false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            certGen.AddExtension(
                X509Extensions.BasicConstraints.Id,
                false,
                new BasicConstraints(false).ToAsn1Object());

            var cert = certGen.Generate(_keyPair.Private);
            var dotnetcert = new X509Certificate2(DotNetUtilities.ToX509Certificate((Org.BouncyCastle.X509.X509Certificate)cert));
            //var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)_keyPair.Private);
            //var rsa = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)_keyPair.Private);
            RSACryptoServiceProvider tempRcsp = (RSACryptoServiceProvider)DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)_keyPair.Private);
            RSACryptoServiceProvider rcsp = new RSACryptoServiceProvider(new CspParameters(1, "Microsoft Strong Cryptographic Provider", new Guid().ToString(), new CryptoKeySecurity(), null));
            rcsp.ImportCspBlob(tempRcsp.ExportCspBlob(true));
            dotnetcert.PrivateKey = rcsp;
            return dotnetcert;
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

        public long SerialNumber { get; set; }

        public CommonName Subject { get; set; }
    }
}
