#include "common.h"

int main(void)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HPOLICY hSRK_Policy,hTPM_Policy;
    TSS_RESULT result;

    result=Tspi_Context_Create(&hContext);
    DBG("Create context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("Connect to native TCS",result);

    result=Tspi_Context_GetTPMObject(hContext,&hTPM);
    DBG("Get TPM handle",result);

    result=Tspi_GetPolicyObject(hTPM,TSS_POLICY_USAGE,&hTPM_Policy);
    DBG("Get Policy handle of TPM",result);

    result=Tspi_Policy_SetSecret(hTPM_Policy,TSS_SECRET_MODE_PLAIN,3,"123");
    DBG("Set TPM policy's secret to 123",result);


}
