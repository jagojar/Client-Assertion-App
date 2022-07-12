# Call the Azure function

1. Url: https://name-func-app.azurewebsites.net/api/GetClientAssertion
2. Method: Post
3. Body request

```json

{
	"keyVaultUrl":"https://{kvname}.vault.azure.net",
	"tenantId":"",
	"confidentialClientID":"",
	"certificateName":"certificate-name-in-key-vault"
}
```

4. Response example: 
```
Client Assertion: eyJhbGciOiJSU...
```
