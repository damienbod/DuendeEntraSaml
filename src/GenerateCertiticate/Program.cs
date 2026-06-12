using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GenerateCertiticate;

class Program
{
    static CreateCertificates? _cc;
    static ImportExportCertificate? _iec;
    static void Main(string[] args)
    {
        var sp = new ServiceCollection()
           .AddCertificateManager()
           .BuildServiceProvider();

        _cc = sp.GetService<CreateCertificates>()!;
        _iec = sp.GetService<ImportExportCertificate>()!;

        var rsaCert = CreateRsaCertificate("localhost", 10);

        var pemPublicRsaKey = _iec.PemExportPublicKeyCertificate(rsaCert);
        File.WriteAllText("rsa256-public.pem", pemPublicRsaKey);

        using (RSA? rsa = rsaCert.GetRSAPrivateKey())
        {
            var pemPrivateRsaKey = rsa!.ExportRSAPrivateKeyPem();
            File.WriteAllText("rsa256-private.pem", pemPrivateRsaKey);
        }

        string password = "1234";
      
        var serverCertInPfxBtyes = _iec.ExportSelfSignedCertificatePfx(password, rsaCert);
        File.WriteAllBytes("saml-signing-rsa.pfx", serverCertInPfxBtyes);


        Console.WriteLine("created, keys are in the bin folder");
    }

    public static X509Certificate2 CreateRsaCertificate(string dnsName, int validityPeriodInYears)
    {
        var basicConstraints = new BasicConstraints
        {
            CertificateAuthority = false,
            HasPathLengthConstraint = false,
            PathLengthConstraint = 0,
            Critical = false
        };

        var subjectAlternativeName = new SubjectAlternativeName
        {
            DnsName = new List<string>
            {
                dnsName,
            }
        };

        var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature;

        // only if certification authentication is used
        var enhancedKeyUsages = new OidCollection
        {
            OidLookup.ClientAuthentication,
            OidLookup.ServerAuthentication 
            // OidLookup.CodeSigning,
            // OidLookup.SecureEmail,
            // OidLookup.TimeStamping  
        };

        var certificate = _cc!.NewRsaSelfSignedCertificate(
            new DistinguishedName { CommonName = dnsName },
            basicConstraints,
            new ValidityPeriod
            {
                ValidFrom = DateTimeOffset.UtcNow,
                ValidTo = DateTimeOffset.UtcNow.AddYears(validityPeriodInYears)
            },
            subjectAlternativeName,
            enhancedKeyUsages,
            x509KeyUsageFlags,
            new RsaConfiguration
            {
                KeySize = 2048,
                HashAlgorithmName = HashAlgorithmName.SHA256
            });

        return certificate;
    }
}

