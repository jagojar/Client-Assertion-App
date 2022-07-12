using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Client_Assertion_App
{
    public class CertificateHelper
    {
        public static X509Certificate2 ParseCertificate(KeyVaultSecret secret)
        {
            if (string.Equals(secret.Properties.ContentType, CertificateContentType.Pkcs12.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                byte[] pfx = Convert.FromBase64String(secret.Value);
                return new X509Certificate2(pfx);
            }

            // For PEM, you'll need to extract the base64-encoded message body.
            // .NET 5.0 introduces the System.Security.Cryptography.PemEncoding class to make this easier.
            if (string.Equals(secret.Properties.ContentType, CertificateContentType.Pem.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                StringBuilder privateKeyBuilder = new StringBuilder();
                StringBuilder publicKeyBuilder = new StringBuilder();

                using StringReader reader = new StringReader(secret.Value);
                StringBuilder currentKeyBuilder = null;

                string line = reader.ReadLine();
                while (line != null)
                {
                    if (line.Equals("-----BEGIN PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase))
                    {
                        currentKeyBuilder = privateKeyBuilder;
                    }
                    else if (line.Equals("-----BEGIN CERTIFICATE-----", StringComparison.OrdinalIgnoreCase))
                    {
                        currentKeyBuilder = publicKeyBuilder;
                    }
                    else if (line.StartsWith("-----", StringComparison.Ordinal))
                    {
                        currentKeyBuilder = null;
                    }
                    else if (currentKeyBuilder is null)
                    {
                        throw new InvalidOperationException("Invalid PEM-encoded certificate.");
                    }
                    else
                    {
                        currentKeyBuilder.Append(line);
                    }

                    line = reader.ReadLine();
                }

                string privateKeyBase64 = privateKeyBuilder?.ToString() ?? throw new InvalidOperationException("No private key found in certificate.");
                string publicKeyBase64 = publicKeyBuilder?.ToString() ?? throw new InvalidOperationException("No public key found in certificate.");

                byte[] privateKey = Convert.FromBase64String(privateKeyBase64);
                byte[] publicKey = Convert.FromBase64String(publicKeyBase64);

                X509Certificate2 certificate = new X509Certificate2(publicKey);

                using RSA rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(privateKey, out _);

                return certificate.CopyWithPrivateKey(rsa);
            }

            throw new NotSupportedException($@"Certificate encoding ""{secret.Properties.ContentType}"" is not supported.");
        }

        public static string ParseSecretName(Uri secretId)
        {
            if (secretId.Segments.Length < 3)
            {
                throw new InvalidOperationException($@"The secret ""{secretId}"" does not contain a valid name.");
            }

            return secretId.Segments[2].TrimEnd('/');
        }

    }

}
