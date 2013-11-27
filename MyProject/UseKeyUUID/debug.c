#include "common.h"
int main()
{
    TSS_HCONTEXT hContext;
    TSS_HKEY hSRK;
    TSS_UUID SRK_UUID=TSS_UUID_SRK;
    Tspi_Context_Create(&hContext);
    Tspi_Context_Connect(hContext,NULL);
    Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,
            SRK_UUID,&hSRK);
    Tspi_Context_Close(hContext);
    return 0;
}
