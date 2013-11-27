#include "common.h"
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,10}}

int main()
{
    TSS_HKEY hBackup_Key,hSRKey;
    TSS_UUID MY_UUID=BACKUP_KEY_UUID;
    TSS_HPOLICY hBackup_Policy,hSRKey_Policy;
    TSS_FLAG initFlags;
    TSS_UUID SRK_UUID=TSS_UUID_SRK;
    BYTE *pubKey;
    UINT32 pubKeySize;
    FILE *fout;
    TSS_RESULT result;
    TSS_HCONTEXT hContext;

    result=Tspi_Context_Create(&hContext); /*创建上下文*/
    DBG("create context",result);

    result=Tspi_Context_Connect(hContext,NULL); /*连接到本地TSP*/
    DBG("connect context to local TCS",result);

    result=Tspi_Context_LoadKeyByUUID(hContext,
            TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSRKey); /*加载SRK*/
    DBG("load the srk",result);

    result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy); /*获取SRK策略对象*/
    DBG("get SRK policy object",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,
            8,"46113200"); /*设置SRK策略秘密*/
    DBG("set secret of hSRKey_Policy",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,
            TSS_POLICY_USAGE,&hBackup_Policy); /*创建策略对象*/
    DBG("create a backup policy object",result);

    result=Tspi_Policy_SetSecret(hBackup_Policy,TSS_SECRET_MODE_PLAIN,3,"123"); /*设置策略对象消息*/
    DBG("set backup policy object secret",result);

    initFlags=TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | 
        TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_RSAKEY,
            initFlags,&hBackup_Key); /*创建hBackup_Key*/
    DBG("create the key object",result);

    result=Tspi_SetAttribUint32(hBackup_Key,TSS_TSPATTRIB_KEY_INFO,
            TSS_TSPATTRIB_KEYINFO_ENCSCHEME,TSS_ES_RSAESPKCSV15); /*设置hBackup_Key填充方式*/
    DBG("set the key's padding type",result);

    result=Tspi_Policy_AssignToObject(hBackup_Policy,hBackup_Key); /*将策略对象hBackup_Policy分配给hBackup_Key*/
    DBG("assign the key's policy to the key",result);
    printf("creating the key could take a while\n");

    result=Tspi_Key_CreateKey(hBackup_Key,hSRKey,0); /*在TPM内创建hBackup_Key,用hSRKey包装它*/
    DBG("asking tpm to create the key",result);

    result=Tspi_Context_RegisterKey(hContext,hBackup_Key,
            TSS_PS_TYPE_SYSTEM,MY_UUID,TSS_PS_TYPE_SYSTEM,SRK_UUID); /*注册hBackup_Key到TPM永久存储区域*/
    DBG("register the key for later retrieval",result);
    printf("registering key blob for later retrieval\r\n");

    result=Tspi_Key_LoadKey(hBackup_Key,hSRKey); /*加载hBackup_Key到TPM*/
    DBG("load key in TPM",result);

    result=Tspi_Key_GetPubKey(hBackup_Key,&pubKeySize,&pubKey); /*获取hBackup_Key的公钥部分*/
    DBG("get public portion of key",result);

    fout=fopen("BackupKey.pub","wb");
    if(fout!=NULL)
    {
        write(fileno(fout),pubKey,pubKeySize); /*将公钥内容写入文件*/
        printf("finished writing BackupKey.pub\n");
        fclose(fout);
    }
    else
        printf("error opening BackupKey.pub\r\n");
    Tspi_Policy_FlushSecret(hBackup_Policy);
    Tspi_Context_Close(hBackup_Key);
    Tspi_Context_Close(hContext);
}
