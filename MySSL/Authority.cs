using System;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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

        private readonly X509Name _issuer;
        private readonly X509V3CertificateGenerator _certGen;
        private readonly BigInteger _authSerial;

        private bool _creatingAuthCert = true;
        private AsymmetricCipherKeyPair _keyPair;

        public Authority(string authority)
        {
            _issuer = new X509Name(new CommonName(authority).Name);
            _authSerial = GetSerialNumber();
            CreateKeyPair();

            _certGen = new X509V3CertificateGenerator();
            _certGen.SetSubjectDN(_issuer);
            _certGen.SetSerialNumber(_authSerial);

            X509Certificate = GenerateCertificate();
            _creatingAuthCert = false;
        }

        public X509Certificate2 X509Certificate
        {
            get;
            private set;
        }

        private void PrepareCertificate()
        {
            _certGen.SetIssuerDN(_issuer);
            _certGen.SetSignatureAlgorithm(SignatureAlgorithm);
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
                new BasicConstraints(_creatingAuthCert).ToAsn1Object());

        }

        /// <summary>
        /// Creates a keypair
        /// </summary>
        /// <returns>AsymmetricCipherKeyPair</returns>
        private void CreateKeyPair()
        {
            var keygen = new RsaKeyPairGenerator();
            keygen.Init(new KeyGenerationParameters(new SecureRandom(), BytesInKeyStrength));
            _keyPair = keygen.GenerateKeyPair();
        }

        /// <summary>
        /// Create a 120-bit serial number
        /// </summary>
        /// <returns>BigInteger serial number</returns>
        private BigInteger GetSerialNumber()
        {
            return BigInteger.ProbablePrime(120, new Random());
        }

        /// <summary>
        /// Creates a trusted certficate
        /// </summary>
        /// <returns>X509Certificate2</returns>
        private X509Certificate2 GenerateCertificate()
        {
            PrepareCertificate();
            var cert = _certGen.Generate(_keyPair.Private);
            _certGen.Reset();
            return new X509Certificate2(DotNetUtilities.ToX509Certificate((Org.BouncyCastle.X509.X509Certificate)cert));
        }

        private AsymmetricAlgorithm GetPrivateKey()
        {
            RSACryptoServiceProvider tempRcsp = (RSACryptoServiceProvider)DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)_keyPair.Private);
            RSACryptoServiceProvider rcsp = new RSACryptoServiceProvider(new CspParameters(1, "Microsoft Strong Cryptographic Provider", new Guid().ToString(), new CryptoKeySecurity(), null));
            rcsp.ImportCspBlob(tempRcsp.ExportCspBlob(true));
            return rcsp;
        }

        public X509Certificate2 GetSSLCertificate()
        {
            _certGen.SetSubjectDN(GetMachineName());
            _certGen.SetSerialNumber(GetSerialNumber()); 

            _certGen.AddExtension(
                X509Extensions.ExtendedKeyUsage.Id,
                false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            var cert = GenerateCertificate();
            cert.PrivateKey = GetPrivateKey();
            return cert;
        }

        private X509Name GetMachineName()
        {
            var cn = new CommonName(Environment.MachineName);
            return new X509Name(cn.Name);
        }
    }
}
