# Client-Assertion-App

Based in the docs:
* [msal-net-client-assertions](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-net-client-assertions)

* [get-certificate-private-key](https://docs.microsoft.com/en-us/samples/azure/azure-sdk-for-net/get-certificate-private-key/)

Java example [link](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-java-token-cache-serialization)

## Install app to generate assertion:

1. Install .net core 3.1 [Windows](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-3.1.26-windows-x64-installer) or [MacOS](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-3.1.26-macos-x64-installer)

2. Download app folder from [app](https://github.com/jagojar/Client-Assertion-App/tree/master/app)

3. Run Client-Assertion-App.exe

## When running the app in IIS: 
1. application pool instance
2. Click advanced settings
3. Under Process model, set Load User Profile to true.

## When running in Azure Web App:
1. Go to Configuration > Application Settings 
2. Add variable WEBSITE_LOAD_USER_PROFILE = 1.

## Azure Function App
1. Publish function to publish folder [guide](https://docs.microsoft.com/en-us/visualstudio/deployment/quickstart-deploy-aspnet-web-app?view=vs-2022&tabs=folder)
2. Create zip with the content of the publish folder
3. Deploy func app with zip with the Azure Cli command:

```
az functionapp deployment source config-zip -g <resource_group> -n <app_name> --src <zip_file_path>
```
4. Test the app with the endpoint:
Post https://{your-func-app-name}.azurewebsites.net/api/GetClientAssertion?code={youraccesscode}
Request Body example
```json
{
	"keyVaultUrl":"https://kv-name.vault.azure.net",
	"tenantId":"xxxx",
	"aud":"api://xxxx"
	"confidentialClientID":"xxxx",
	"certificateName":"exampleCert"
}
```
