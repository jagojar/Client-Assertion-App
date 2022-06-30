using Microsoft.Identity.Client;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Client_Assertion_App
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var CertificateName = "CN=DaemonConsoleCert";
            var tenantId = "fbfaa8eb-7973-4ed4-ab2d-41938712c70f";
            var ConfidentialClientID = "57db9c3f-a4e4-421f-a380-eb8beef923a1";

            X509Certificate2 certificate = ReadCertificate(CertificateName);
            string signedClientAssertion = ClientAssertionHelper.GetSignedClientAssertion(certificate, tenantId, ConfidentialClientID);
            // OR
            //string signedClientAssertion = GetSignedClientAssertionAlt(certificate);

            var confidentialApp = ConfidentialClientApplicationBuilder
                .Create(ConfidentialClientID)
                .WithClientAssertion(signedClientAssertion)
                .Build();

            Console.WriteLine("Program with Client Assertion");
            Console.WriteLine("-----------------------------");
            Console.WriteLine();
            Console.WriteLine("Client Assertion: {0}", signedClientAssertion);
            Console.ReadLine();
        }

        private static X509Certificate2 ReadCertificate(string certificateName)
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
    }
}
