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
            Console.WriteLine("Program with Client Assertion");
            Console.WriteLine("-----------------------------");
            Console.WriteLine();

            //var CertificateName = Console.ReadLine();
            //var tenantId = "00000000-0000-0000-0000-000000000000";
            //var ConfidentialClientID = "00000000-0000-0000-0000-000000000000";

            Console.Write("Enter Certificate Name (Example: CN=DaemonConsoleCert): ");
            var CertificateName = Console.ReadLine();

            Console.Write("Enter Tenant Id: ");
            var tenantId = Console.ReadLine();
            
            Console.Write("Enter Client Id: ");
            var ConfidentialClientID = Console.ReadLine();

            X509Certificate2 certificate = ReadCertificate(CertificateName);
            string signedClientAssertion = ClientAssertionHelper.GetSignedClientAssertion(certificate, tenantId, ConfidentialClientID);
            // OR
            //string signedClientAssertion = GetSignedClientAssertionAlt(certificate);

            var confidentialApp = ConfidentialClientApplicationBuilder
                .Create(ConfidentialClientID)
                .WithClientAssertion(signedClientAssertion)
                .Build();

            Console.WriteLine();
            Console.WriteLine("Client Assertion:");
            Console.WriteLine(signedClientAssertion);
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
