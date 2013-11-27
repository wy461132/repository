#ifndef __KEYS_H
#define __KEYS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#define DBG(message,tResult) printf("[%s:%d:%s] "\
                                    "<%s>%s. return:0x%08x.\n",\
                                    __FILE__,__LINE__,__func__,\
                                    (char*) Trspi_Error_String(tResult),\
                                    message,tResult)

#define TPMSEAL_RSA_BEGIN "----RSA KEY BEGIN---\n"
#define TPMSEAL_RSA_END "----RSA KEY END---\n"
#define TPMSEAL_SYM_BEGIN "----SYM KEY BEGIN---\n"
#define TPMSEAL_SYM_END "----SYM KEY END---\n"
#define TPMSEAL_DATA_BEGIN "----ENC DATA BEGIN---\n"
#define TPMSEAL_DATA_END "----ENC DATA END---\n"

#define TPMSEAL_BEGIN_STRING "-----BEGIN TPMSEAL-----\n"
#define TPMSEAL_END_STRING "-----END TPMSEAL-----\n"
#define TPMSEAL_RSA_STRING "-----RSA  SEAL KEY-----\n"
#define TPMSEAL_SYM_STRING "-----SYMMETRIC KEY-----\n"
#define TPMSEAL_DATA_STRING "-----ENC DATA-----\n"

#define TPMSEAL_KEYTYPE_RSA "RSA 2048\n"
#define TPMSEAL_KEYTYPE_SYM "Symmetric Key: "
#define TPMSEAL_CIPHER_AES256CBC "AES-256-CBC\n"
#define TPMSEAL_IV NULL

#define AES_256_LEN 32
typedef struct tss_s tss_t;
struct tss_s{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
};

int tss_init(tss_t **ptss);

int output(unsigned char *begin_str,unsigned char *end_str,
            unsigned char *data,int len,unsigned char *out_filename);
/* Notice: *len is Max data len,and changed to its true len when return*/
int input(unsigned char *begin_str,unsigned char *end_str,
            unsigned char **pdata,int *plen,unsigned char *in_filename);

int symkey_gen(tss_t *tss,unsigned char **psymKey);
int rsakey_gen(tss_t *tss,TSS_HKEY *phKey, int pwd_len,unsigned char *pwd);

int rsakey_seal_symkey(tss_t *tss,TSS_HKEY hKey, unsigned char *symKey,
                        int pwd_len,unsigned char *pwd,
                        unsigned char *rsa_filename,
                        unsigned char *sym_filename);

int rsakey_get(tss_t *tss,TSS_HKEY *phKey,int pwd_len,
        unsigned char *pwd,unsigned char *rsa_filename);

int rsakey_unseal_symkey(tss_t *tss,TSS_HKEY hKey,unsigned char **psymKey,
                        int *psymKeyLen, int pwd_len,unsigned char *pwd, 
                        unsigned char *sym_filename);

int symKey_enc(unsigned char *symKey,unsigned char *data,int len,
                unsigned char *sym_filename);

int symKey_dec(unsigned char *symKey,unsigned char **pdata,int *plen, 
                unsigned char *data_filename);

#endif
