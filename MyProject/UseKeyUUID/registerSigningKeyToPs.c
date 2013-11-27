#include "common.h"
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,11}}

int main()
{
    TSS_HCONTEXT hContext;
    TSS_HPOLICY  hSRKey_Policy;
    TSS_HKEY     hSignKey,hSRKey;
    TSS_UUID     MY_UUID=SIGN_KEY_UUID,SRK_UUID=TSS_UUID_SRK;
    TSS_FLAG     initFlags;
    TSS_RESULT   result;
    BYTE         *pubKey;
    UINT32       pubKeySize;
    FILE         *fout;

    initFlags=TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 |
        TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

    result=Tspi_Context_Create(&hContext);
    DBG("create context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("connect context to native TCS",result);

    result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,
            SRK_UUID,&hSRKey);
    DBG("load SRK",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy);
    DBG("get policy of SRK",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,
            8,"46113200");
    DBG("set policy secret of SRK",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_RSAKEY,
            initFlags,&hSignKey);
    DBG("create the key object",result);

    result=Tspi_SetAttribUint32(hSignKey,TSS_TSPATTRIB_KEY_INFO,
            TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
            TSS_ES_RSAESPKCSV15);
    DBG("set the key's padding type",result);

    printf("creating the key could take a while\n");

    result=Tspi_Key_CreateKey(hSignKey,hSRKey,0);
    DBG("asking tpm to create the key",result);

    result=Tspi_Context_RegisterKey(hContext,hSignKey,TSS_PS_TYPE_SYSTEM,
            MY_UUID,TSS_PS_TYPE_SYSTEM,SRK_UUID);
    DBG("register the key for later retrieval",result);

    printf("register key blob for later retrieval\r\n");

    result=Tspi_Key_LoadKey(hSignKey,hSRKey);
    DBG("load key in TPM",result);

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
        printf("error opening SignKey.pub\r\n");

    Tspi_Context_CloseObject(hContext,hSignKey);
    DBG("close object hSignKey",result);

    Tspi_Context_Close(hContext);
    DBG("close hContext",result);
}
