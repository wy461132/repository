#include "common.h"
 
int main()
{
    TSS_HCONTEXT hContext;
    TSS_HKEY hBindKey;
    TSS_HENCDATA hEncData;
    TSS_FLAG initFlags;
    TSS_RESULT result;
    UINT32 ulDataLength;
    BYTE *rgbBindData,newPubKey[284],*encData="abcdefg hijklmn";
    FILE *fin=fopen("key.pub","r");
    read(fileno(fin),newPubKey,284);
    fclose(fin);
    int i;
    for(i=0;i<284;i++)
    {
        printf("%x",newPubKey[i]);
        if((i+1)%10==0)
            printf("\n");
    }
    printf("\n");

    result=Tspi_Context_Create(&hContext);
    DBG("Create context",result);

    result=Tspi_Context_Connect(hContext,NULL);
    DBG("Connect to native TCS",result);

    initFlags=TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | 
        TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_RSAKEY,
            initFlags,&hBindKey);
    DBG("Create binding key object hBindKey",result);

    result=Tspi_SetAttribData(hBindKey,TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,284,newPubKey);
    DBG("Set public key int key object hBindKey",result);

    result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_ENCDATA,
            TSS_ENCDATA_BIND,&hEncData);
    DBG("Create encdata object",result);

    result=Tspi_Data_Bind(hEncData,hBindKey,15,encData);
    DBG("Bind data",result);

    result=Tspi_GetAttribData(hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,
            TSS_TSPATTRIB_ENCDATABLOB_BLOB,&ulDataLength,&rgbBindData);
    DBG("Get encrypted data",result);

    FILE *fout=fopen("bind.data","wb");
    write(fileno(fout),rgbBindData,ulDataLength);
    fclose(fout);

    result=Tspi_Context_CloseObject(hContext,hBindKey);
    DBG("Close object hBindKey",result);

    result=Tspi_Context_Close(hContext);
    DBG("Close context",result);
}
