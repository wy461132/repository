#include "common.h"
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,11}}

int main()
{
    TSS_HCONTEXT hContext;
    TSS_HPOLICY hSRKey_Policy;
    TSS_HKEY hSignKey,hSRKey;
    TSS_UUID MY_UUID=SIGN_KEY_UUID,SRK_UUID=TSS_UUID_SRK;
    TSS_RESULT result;
    BYTE *pubKey;
    UINT32 pubKeySize;
    FILE *fout;

    result=Tspi_Context_Create(&hContext);
    DBG("create context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("connect context to native TCS",result);

    result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,
            SRK_UUID,&hSRKey);
    DBG("load hSRKey",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy);
    DBG("get policy of hSRKey",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,
            8,"46113200");
    DBG("set policy secret of hSRKey",result);

    result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,
            MY_UUID,&hSignKey);
    DBG("load hSignKey",result);

    result=Tspi_Key_GetPubKey(hSignKey,&pubKeySize,&pubKey);
    DBG("get public portion of key",result);

    fout=fopen("SignKey.pub","wb");
    if(fout!=NULL)
    {
        write(fileno(fout),pubKey,pubKeySize);
        printf("finished writing SignKey.pub\n");
        fclose(fout);
    }
    else
        printf("error opening SignKey.put\r\n");

    Tspi_Context_Close(hContext);
    DBG("close hContext",result);
}
