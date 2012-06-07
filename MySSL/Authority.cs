using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MySSL
{
    /// <summary>
    /// An Authority is a certificate that is trusted and authorized to issue certificates.
    /// </summary>
    public class Authority
    {
        const string SignatureAlgorithm = "SHA1WithRSAEncryption";
        const int BytesInKeyStrength = 1024;

        //private readonly DateTime DefaultExpirationDate = new DateTime(2039, 12, 31);
        private readonly X509Name _issuer;
        private readonly X509V3CertificateGenerator _certGen;

        //private DateTime _effectiveDate = DateTime.Today;
        //private AsymmetricCipherKeyPair _keyPair;
        private BigInteger _authSerial;
        X509Certificate2 _cert;

        public Authority(string authority)
        {
            _issuer = new X509Name(new CommonName(authority).Name);
            _authSerial = BigInteger.ProbablePrime(120, new Random());

            _certGen = new X509V3CertificateGenerator();
            _certGen.SetSignatureAlgorithm(SignatureAlgorithm);
            _certGen.SetIssuerDN(_issuer);
            _certGen.SetSubjectDN(_issuer);
            _cert = GenerateCertificate();
        }

        public X509Certificate2 X509Certificate
        {
            get { return _cert; }
        }

        /// <summary>
        /// Creates a trusted certficate
        /// </summary>
        /// <returns>X509Certificate2</returns>
        private X509Certificate2 GenerateCertificate()
        {
            var _keyPair = CreateKeyPair();

            if (X509Certificate == null) // generating auth certificate
                _certGen.SetSerialNumber(_authSerial);
            else
                _certGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));

            _certGen.SetNotBefore(DateTime.Today);
            _certGen.SetNotAfter(DateTime.MaxValue);
            _certGen.SetPublicKey(_keyPair.Public);

            _certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier.Id,
                false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public),
                    new GeneralNames(new GeneralName(_issuer)), _authSerial));

            _certGen.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(true).ToAsn1Object());

            var cert = _certGen.Generate(_keyPair.Private);
            return new X509Certificate2(DotNetUtilities.ToX509Certificate((Org.BouncyCastle.X509.X509Certificate)cert));
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

        public X509Certificate2 GetSSLCertificate()
        {
            _certGen.Reset();
            _certGen.SetSignatureAlgorithm(SignatureAlgorithm);
            _certGen.SetIssuerDN(_issuer);
            _certGen.SetSubjectDN(GetMachineName());
            _certGen.AddExtension(
                X509Extensions.ExtendedKeyUsage.Id,
                false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            return GenerateCertificate();
        }

        private X509Name GetMachineName()
        {
            var cn = new CommonName(Environment.MachineName);
            return new X509Name(cn.Name);
        }
    }
}
