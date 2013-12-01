#include "common.h"
#define STORAGE_KEY_UUID {0,0,0,0,0,{0,0,0,0,2,12}}

int main(void)
{
    TSS_HKEY hStorage_Key,hSRKey;
	TSS_UUID STORAGE_UUID=STORAGE_KEY_UUID;
	TSS_HPOLICY hSRKey_Policy,hStorage_Policy;
	TSS_FLAG initFlags;
	TSS_UUID SRK_UUID=TSS_UUID_SRK;
	BYTE *pubKey;
	UINT32 pubKeySize;
	FILE *fout;
	TSS_RESULT result;
	TSS_HCONTEXT hContext;

	result=Tspi_Context_Create(&hContext);
	DBG("Create context",result);

	result=Tspi_Context_Connect(hContext,NULL);
	DBG("Connect context to local TCS",result);

	result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,
			SRK_UUID,&hSRKey);
	DBG("Load the SRK",result);

	result=Tspi_GetPolicyObject(hSRKey,TSS_POLICY_USAGE,&hSRKey_Policy);
	DBG("Get secret of hSRKey_Policy",result);

    result=Tspi_Policy_SetSecret(hSRKey_Policy,TSS_SECRET_MODE_PLAIN,8,"46113200");
	DBG("Set secret of hSRKey_Policy",result);

	initFlags=TSS_KEY_TYPE_STORAGE |TSS_KEY_SIZE_2048 | TSS_KEY_AUTHORIZATION |
        TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;
	result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_RSAKEY,initFlags,&hStorage_Key);
	DBG("Create the Storage_Key object",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,TSS_POLICY_USAGE,
            &hStorage_Policy);
    DBG("Create hStorage_Policy",result);

    result=Tspi_Policy_SetSecret(hStorage_Policy,TSS_SECRET_MODE_PLAIN,3,"123");
    DBG("Set secret of hStorage_Policy",result);

    result=Tspi_Policy_AssignToObject(hStorage_Policy,hStorage_Key);
    DBG("Assign hStorage_Policy to hStorage_Key",result);

	result=Tspi_Key_CreateKey(hStorage_Key,hSRKey,0);
	DBG("Asking tpm to create the key",result);

/*	result=Tspi_Context_RegisterKey(hContext,hStorage_Key,TSS_PS_TYPE_SYSTEM,
            STORAGE_UUID,TSS_PS_TYPE_SYSTEM,SRK_UUID);
	DBG("Register hStorage_key to PS",result);
*/
    result=Tspi_Context_UnregisterKey(hContext,TSS_PS_TYPE_SYSTEM,STORAGE_UUID,
            &hStorage_Key);
    DBG("Unregister hStorage_Key",result);

	result=Tspi_Key_LoadKey(hStorage_Key,hSRKey);
	DBG("Load hStorage_key in TPM",result);

	result=Tspi_Key_GetPubKey(hStorage_Key,&pubKeySize,&pubKey);
	DBG("Get public portion of hStorage_Key",result);

	fout=fopen("StorageKey.pub","wb");
	if(fout!=NULL)
	{
		write(fileno(fout),pubKey,pubKeySize);
		printf("Finished writing StorageKey.pub\n");
		fclose(fout);
	}
	else
		printf("Error opening StorageKey.pub\n");
	Tspi_Context_CloseObject(hContext,hStorage_Key);
	DBG("Close hStorage_Key Object",result);

	Tspi_Context_Close(hContext);
	DBG("Close hContext Object",result);
}

