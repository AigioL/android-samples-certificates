using System;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Android.Widget;
using Context = Android.Content.Context;

#nullable enable

static class CertificateHelper
{
    public const int KEY_SIZE_BITS = 2048;

    static readonly SecureRandom secureRandom = new SecureRandom();

    public static X509Certificate2 CreateRootCertificate(string pfxFilePath, string rootCertificateName = "My Certificate")
    {
        var validFrom = DateTime.Today.AddDays(-1);
        var validTo = DateTime.Today.AddDays(300);

        return GenerateBySelfPfx(new[] { rootCertificateName }, KEY_SIZE_BITS, validFrom, validTo, pfxFilePath);
    }

    static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
    {
        var keygenParam = new KeyGenerationParameters(secureRandom, length);
        var keyGenerator = new RsaKeyPairGenerator();
        keyGenerator.Init(keygenParam);
        return keyGenerator.GenerateKeyPair();
    }

    static X509Certificate2 GenerateBySelfPfx(IEnumerable<string> domains, int keySizeBits, DateTime validFrom, DateTime validTo, string? caPfxPath, string? password = default)
    {
        var keys = GenerateRsaKeyPair(keySizeBits);
        var cert = GenerateCertificate(domains, keys.Public, validFrom, validTo, domains.First(), null, keys.Private, 1);

        var x509Certificate = WithPrivateKey(cert, keys.Private);

        if (!string.IsNullOrEmpty(caPfxPath))
        {
            byte[] exported = x509Certificate.Export(X509ContentType.Pkcs12, password);
            File.WriteAllBytes(caPfxPath, exported);
        }

        return x509Certificate;
    }

    static X509Certificate GenerateCertificate(IEnumerable<string> domains, AsymmetricKeyParameter subjectPublic, DateTime validFrom, DateTime validTo, string issuerName, AsymmetricKeyParameter? issuerPublic, AsymmetricKeyParameter issuerPrivate, int? caPathLengthConstraint)
    {
        var signatureFactory = issuerPrivate is ECPrivateKeyParameters
            ? new Asn1SignatureFactory(X9ObjectIdentifiers.ECDsaWithSha256.ToString(), issuerPrivate)
            : new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerPrivate);

        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetIssuerDN(new X509Name("CN=" + issuerName));
        certGenerator.SetSubjectDN(new X509Name("CN=" + domains.First()));
        certGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenerator.SetNotBefore(validFrom);
        certGenerator.SetNotAfter(validTo);
        certGenerator.SetPublicKey(subjectPublic);

        if (issuerPublic != null)
        {
            var akis = new AuthorityKeyIdentifierStructure(issuerPublic);
            certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, akis);
        }

        if (caPathLengthConstraint != null && caPathLengthConstraint >= 0)
        {
            var basicConstraints = new BasicConstraints(caPathLengthConstraint.Value);
            certGenerator.AddExtension(X509Extensions.BasicConstraints, true, basicConstraints);
            certGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.CrlSign | KeyUsage.KeyCertSign));
        }
        else
        {
            var basicConstraints = new BasicConstraints(cA: false);
            certGenerator.AddExtension(X509Extensions.BasicConstraints, true, basicConstraints);
            certGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
        }
        certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

        var names = domains.Select(domain =>
        {
            var nameType = GeneralName.DnsName;
            if (IPAddress.TryParse(domain, out _))
            {
                nameType = GeneralName.IPAddress;
            }
            return new GeneralName(nameType, domain);
        }).ToArray();

        var subjectAltName = new GeneralNames(names);
        certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
        return certGenerator.Generate(signatureFactory);
    }

    static X509Certificate2 WithPrivateKey(X509Certificate certificate, AsymmetricKeyParameter privateKey)
    {
        const string password = "password";
        Pkcs12Store store;

        //if (IsRunningOnMono())
        //{
        var builder = new Pkcs12StoreBuilder();
        builder.SetUseDerEncoding(true);
        store = builder.Build();
        //}
        //else
        //{
        //    store = new Pkcs12Store();
        //}

        var entry = new X509CertificateEntry(certificate);
        store.SetCertificateEntry(certificate.SubjectDN.ToString(), entry);

        store.SetKeyEntry(certificate.SubjectDN.ToString(), new AsymmetricKeyEntry(privateKey), new[] { entry });
        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), new SecureRandom(new CryptoApiRandomGenerator()));

        return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable);
    }

    public static void TestCreateRootCertificate(Context context)
    {
        try
        {
            var path = Path.Combine(context.DataDir.CanonicalPath, "1.pfx");
            var cert = CreateRootCertificate(path);
            var msg = $"OK, SHA1: {cert.GetCertHashString()}";
            Toast.MakeText(context, msg, ToastLength.Long).Show();
        }
        catch (Exception e)
        {
            var error = e.ToString();
            Toast.MakeText(context, error, ToastLength.Long).Show();
        }
    }
}
