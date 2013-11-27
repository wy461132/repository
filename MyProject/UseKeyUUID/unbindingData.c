#include "common.h"
#include <unistd.h>
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,10}}

int main()
{
    TSS_HCONTEXT hContext;
    TSS_HKEY hBindKey,hSRKey;
    TSS_HPOLICY hBind_Policy,hSRKey_Policy;
    TSS_HENCDATA hEncData;
    TSS_RESULT result;
    TSS_UUID SRK_UUID=TSS_UUID_SRK,BIND_UUID=BACKUP_KEY_UUID;

    UINT32 encLen=256;
    BYTE encryptedData[256];
    BYTE *rgbDataUnbind;
    UINT32 ulDataLength;
    FILE *fin;

    result=Tspi_Context_Create(&hContext);
    DBG("Create context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("Connect to native TCS",result);

    fin=fopen("bind.data","rb");
    read(fileno(fin),encryptedData,encLen);
    fclose(fin);

    result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,
            &hSRKey);
    DBG("Load SRK",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy);
    DBG("Get SRK policy object",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,
            8,(BYTE *)"46113200");
    DBG("Set secret of SRK policy",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_ENCDATA,
            TSS_ENCDATA_BIND,&hEncData);
    DBG("Created Data object",result);

    result=Tspi_SetAttribData(hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,
            TSS_TSPATTRIB_ENCDATABLOB_BLOB,encLen,encryptedData);
    DBG("Set hEncdata object",result);

    result=Tspi_Context_GetKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,BIND_UUID,
            &hBindKey);
    DBG("Get unbinding key",result);

    result=Tspi_Key_LoadKey(hBindKey,hSRKey);
    DBG("Load unbinding key",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hBind_Policy);
    DBG("Get unbinding key policy",result);

    result=Tspi_Policy_SetSecret(hBind_Policy,TSS_SECRET_MODE_PLAIN,
            3,(BYTE *)"123");
    DBG("Set secret of unbinding key policy",result);

    result=Tspi_Data_Unbind(hEncData,hBindKey,&ulDataLength,&rgbDataUnbind);
    DBG("Unbind",result);

    int i;
    for(i=0;i<ulDataLength;i++)
        printf("%c",rgbDataUnbind[i]);
    printf("\n");

    result=Tspi_Context_CloseObject(hContext,hEncData);
    DBG("Close hEncData",result);

    result=Tspi_Context_Close(hContext);
    DBG("Close context",result);

    return 0;
}
