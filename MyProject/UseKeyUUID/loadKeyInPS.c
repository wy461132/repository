#include "common.h"
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,10}}

int main()
{
    TSS_HKEY hBackup_Key,hSRKey;
    TSS_UUID MY_UUID=BACKUP_KEY_UUID;
    TSS_UUID SRK_UUID=TSS_UUID_SRK;
    TSS_HPOLICY hSRKey_Policy,hBackup_Policy;
    BYTE *pubKey;
    UINT32 pubKeySize;
    FILE *fout;
    TSS_RESULT result;
    TSS_HCONTEXT hContext;

    result=Tspi_Context_Create(&hContext);
    DBG("create context",result);
    
    result=Tspi_Context_Connect(hContext,NULL);
    DBG("connect context to local TCS",result);
    
    result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,
            &hSRKey);
    DBG("load the srk",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy);
    DBG("get SRK policy object",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,
            8,"46113200");
    DBG("set secret of hSRKey_Policy",result);
    
    result=Tspi_Context_GetKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,MY_UUID,
            &hBackup_Key);
    DBG("get hBackup_Key",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,
            TSS_POLICY_USAGE,&hBackup_Policy);
    DBG("create policy object hBackup_Policy",result);

    result=Tspi_Policy_SetSecret(hBackup_Policy,TSS_SECRET_MODE_PLAIN,3,"123");
    DBG("set secret of hBackup_Policy",result);

    result=Tspi_Policy_AssignToObject(hBackup_Policy,hBackup_Key);
    DBG("assign hBackup_Policy to hBackup_Key",result);
 
    result=Tspi_Key_LoadKey(hBackup_Key,hSRKey);
    DBG("load hBackup_Key",result);

    result=Tspi_Key_GetPubKey(hBackup_Key,&pubKeySize,&pubKey);
    DBG("get public portion of key",result);

    fout=fopen("key.pub","wb");
    if(fout!=NULL)
    {
        write(fileno(fout),pubKey,pubKeySize);
        printf("finished writing key.pub\n");
        fclose(fout);
    }
    else
        printf("error opening key.pub\r\n");
    Tspi_Context_Close(hBackup_Key);
    Tspi_Context_Close(hContext);

}
