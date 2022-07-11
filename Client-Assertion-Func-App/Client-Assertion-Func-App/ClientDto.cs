using System;
using System.Collections.Generic;
using System.Text;

namespace Client_Assertion_Func_App
{
    public class ClientDto
    {
        public string keyVaultUrl { get; set; }
        public string tenantId { get; set; }
        public string confidentialClientID { get; set; }
        public string certificateName { get; set; }
    }
}
