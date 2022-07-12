using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;

namespace Client_Assertion_Func_App
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string responseMessage = "";

            try
            {
                log.LogInformation("C# HTTP trigger function starting...");
                

                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                ClientDto data = JsonConvert.DeserializeObject<ClientDto>(requestBody);
                string keyVaultUrl = data.keyVaultUrl;
                string tenantId = data.tenantId;
                string confidentialClientID = data.confidentialClientID;
                string certificateName = data.certificateName;

                log.LogInformation("Body request processed...");

                X509Certificate2 certificate = ClientAssertionHelper.ReadCertificateFromKeyVault(keyVaultUrl, certificateName);
                log.LogInformation("Certificate retrieved from key vault {keyVaultUrl}...", keyVaultUrl);

                string signedClientAssertion = ClientAssertionHelper.GetSignedClientAssertion(certificate, tenantId, confidentialClientID);
                log.LogInformation("Client assertion generated");

                responseMessage = "Client Assertion: " + signedClientAssertion;

            }
            catch (Exception ex)
            {
                responseMessage = ex.Message;
            }

            
            return new OkObjectResult(responseMessage);
        }
    }
}
