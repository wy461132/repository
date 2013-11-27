#include"common.h"
#include<openssl/bn.h>
int main(int args,char **argv)
{
    BIGNUM *num=BN_new();
    BN_set_word(num,256);
    printf("%d\n",BN_num_bytes(num));
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_RESULT result;
    TSS_HKEY hSRK=0;
    TSS_HPOLICY hSRKPolicy=0;
    TSS_UUID SRK_UUID=TSS_UUID_SRK;
    BYTE *secret="46113200";

    result=Tspi_Context_Create(&hContext);
    DBG("Create Context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("Context Connect",result);

    result=Tspi_Context_GetTpmObject(hContext,&hTPM);
    DBG("Get TPM Handle",result);

    result=Tspi_Context_LoadKeyByUUID(hContext,
            TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSRK);
    DBG("Got the SRK handle",result);

    result=Tspi_GetPolicyObject(hSRK,TSS_POLICY_USAGE,
            &hSRKPolicy);
    DBG("Got the SRK policy",result);

    result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_PLAIN,
            8,secret);
    DBG("Set the SRK secret in its policy",result);

    Tspi_Context_FreeMemory(hContext,NULL);
    Tspi_Context_Close(hContext);
    return 0;
}
