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
            string keyVaultUrl = "";
            string tenantId = "";
            string confidentialClientID = "";
            string certificateName = "";

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            ClientDto data = JsonConvert.DeserializeObject<ClientDto>(requestBody);
            keyVaultUrl = data.keyVaultUrl;
            tenantId = data.tenantId;
            confidentialClientID = data.confidentialClientID;
            certificateName = data.certificateName;

            X509Certificate2 certificate = ClientAssertionHelper.ReadCertificateFromKeyVault(keyVaultUrl, certificateName);
            string signedClientAssertion = ClientAssertionHelper.GetSignedClientAssertion(certificate, tenantId, confidentialClientID);


            //log.LogInformation("C# HTTP trigger function processed a request.");

            //string name = req.Query["name"];

            //string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            //dynamic data = JsonConvert.DeserializeObject(requestBody);
            //name = name ?? data?.name;

            //string responseMessage = string.IsNullOrEmpty(name)
            //    ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
            //    : $"Hello, {name}. This HTTP triggered function executed successfully.";

            string responseMessage = string.IsNullOrEmpty(keyVaultUrl)
                ? "keyVaultUrl not provided"
                : "Client Assertion: " + signedClientAssertion;

            return new OkObjectResult(responseMessage);
        }
    }
}
