using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Client_Assertion_Func_App
{
    public class ClientAssertionHelper
    {
        private static IDictionary<string, object> GetClaims(string tenantId, string clientId)
        {
            //aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
            string aud = $"https://login.microsoftonline.com/{tenantId}/v2.0";

            string ConfidentialClientID = clientId; //client id 00000000-0000-0000-0000-000000000000
            const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
            DateTimeOffset validFrom = DateTimeOffset.UtcNow;
            DateTimeOffset validUntil = validFrom.AddSeconds(JwtToAadLifetimeInSeconds);

            return new Dictionary<string, object>()
            {
                { "aud", aud },
                { "exp", validUntil.ToUnixTimeSeconds() },
                { "iss", ConfidentialClientID },
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", validFrom.ToUnixTimeSeconds() },
                { "sub", ConfidentialClientID },
                { "iat", validFrom.ToUnixTimeSeconds()},
            };
        }

        public static string Base64UrlEncode(byte[] arg)
        {
            char Base64PadCharacter = '=';
            char Base64Character62 = '+';
            char Base64Character63 = '/';
            char Base64UrlCharacter62 = '-';
            char Base64UrlCharacter63 = '_';

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }

        public static string GetSignedClientAssertion(X509Certificate2 certificate, string tenantId, string clientId)
        {
            // Get the RSA with the private key, used for signing.
            var rsa = certificate.GetRSAPrivateKey();

            //alg represents the desired signing algorithm, which is SHA-256 in this case
            //x5t represents the certificate thumbprint base64 url encoded
            var header = new Dictionary<string, string>()
            {
                { "alg", "RS256"},
                { "typ", "JWT" },
                { "x5t", Base64UrlEncode(certificate.GetCertHash()) }
            };

            //Please see the previous code snippet on how to craft claims for the GetClaims() method
            var claims = GetClaims(tenantId, clientId);

            var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
            var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(claims);
            string token = Base64UrlEncode(headerBytes) + "." + Base64UrlEncode(claimsBytes);

            string signature = Base64UrlEncode(rsa.SignData(Encoding.UTF8.GetBytes(token), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            string signedClientAssertion = string.Concat(token, ".", signature);
            return signedClientAssertion;
        }

        public static string GetSignedClientAssertionAlt(X509Certificate2 certificate, string tenantId, string clientId)
        {
            //aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
            string aud = $"https://login.microsoftonline.com/{tenantId}/v2.0";

            // client_id
            string confidentialClientID = clientId; // "00000000-0000-0000-0000-000000000000";

            // no need to add exp, nbf as JsonWebTokenHandler will add them by default.
            var claims = new Dictionary<string, object>()
            {
                { "aud", aud },
                { "iss", confidentialClientID },
                { "jti", Guid.NewGuid().ToString() },
                { "sub", confidentialClientID }
            };

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = claims,
                SigningCredentials = new X509SigningCredentials(certificate)
            };

            var handler = new JsonWebTokenHandler();
            var signedClientAssertion = handler.CreateToken(securityTokenDescriptor);

            return signedClientAssertion;
        }

        public static X509Certificate2 ReadCertificate(string certificateName)
        {
            if (string.IsNullOrWhiteSpace(certificateName))
            {
                throw new ArgumentException("certificateName should not be empty. Please set the CertificateName setting in the appsettings.json", "certificateName");
            }
            X509Certificate2 cert = null;

            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = store.Certificates;

                // Find unexpired certificates.
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                // From the collection of unexpired certificates, find the ones with the correct name.
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certificateName, false);

                // Return the first certificate in the collection, has the right name and is current.
                cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            }
            return cert;
        }

        public static X509Certificate2 ReadCertificateFromKeyVault(string vaultUrl, string certificateName)
        {
            var client = new CertificateClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());

            KeyVaultCertificateWithPolicy certificateWithPolicy = client.GetCertificate(certificateName);
            X509Certificate2 certificate = new X509Certificate2(certificateWithPolicy.Cer);

            return certificate;
        }
    }
}
