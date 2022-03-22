 /*
  * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
  * Description: cms signature auth
  * Author: wangchunxu1@huawei.com
  * Create: 2020.06.18
  */

#include "tee_cmscbb.h"
#include "tee_mem_mgmt_api.h"
#include <string.h>

static uint32_t get_params_buffer_effective_len(const uint8_t *param_buff, uint32_t param_len)
{
    while (param_len != 0) {
        if (param_buff[param_len - 1] != 0)
            break;
        param_len--;
    }
    return param_len;
}

static RSA *get_rsa_key(const CmscbbBigInt *e, const CmscbbBigInt *n)
{
    uint32_t bn_n_len = get_params_buffer_effective_len(n->aVal, CMSCBB_MAX_INT_DIGITS);
    uint32_t bn_e_len = get_params_buffer_effective_len(e->aVal, CMSCBB_MAX_INT_DIGITS);
    BIGNUM *bn_n = BN_bin2bn(n->aVal, bn_n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e->aVal, bn_e_len, NULL);
    RSA *rsa_key = NULL;
    if ((bn_n == NULL) || (bn_e == NULL)) {
        tloge("CMSCBB: Change pub buffer num to big num failed\n");
        goto EXIT;
    }

    rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("CMSCBB: Malloc memory for rsa key failed\n");
        goto EXIT;
    }

    int res = RSA_set0_key(rsa_key, bn_n, bn_e, NULL);
    if (res != CVB_TRUE) {
        tloge("CMSCBB: Set rsa key failed\n");
        goto EXIT;
    }

    return rsa_key;

EXIT:
    BN_free(bn_n);
    BN_free(bn_e);
    RSA_free(rsa_key);
    return NULL;
}

static void put_rsa_key(gt_crypto_vrf *pvrf)
{
    if (pvrf != NULL) {
        if (pvrf->rsa_key != NULL) {
            RSA_free(pvrf->rsa_key);
            pvrf->rsa_key = NULL;
        }
    }
}

CMSCBB_ERROR_CODE CmscbbMalloc(CVB_VOID **ppByte, CVB_SIZE_T size)
{
    if (ppByte == NULL || size == 0) {
        tloge("CMSCBB: ppByte is NULL or size is 0\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    *ppByte = TEE_Malloc(size, 0);
    if (*ppByte == NULL) {
        tloge("CMSCBB: malloc failed\n");
        return CMSCBB_ERR_SYS_MEM_ALLOC;
    }

    return CVB_SUCCESS;
}

CVB_VOID CmscbbFree(CVB_VOID* ptr)
{
    if (ptr != NULL)
        TEE_Free(ptr);
}

CVB_INT CmscbbMemCmp(const CVB_VOID* s1, const CVB_VOID* s2, CVB_SIZE_T n)
{
    if (s1 == NULL || s2 == NULL) {
        tloge("CMSCBB: mem s1 or s2 is NULL\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    return TEE_MemCompare(s1, s2, n);
}

CVB_INT CmscbbStrNCmp(const CVB_CHAR* s1, const CVB_CHAR* s2, CVB_SIZE_T n)
{
    if (s1 == NULL || s2 == NULL) {
        tloge("CMSCBB: str s1 or s2 is NULL\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    return strncmp(s1, s2, n);
}

const CVB_CHAR* CmscbbStrStr(const CVB_CHAR* haystack, const CVB_CHAR* needle)
{
    if (haystack == NULL || needle == NULL) {
        tloge("CMSCBB: str haystack or needle is NULL\n");
        return NULL;
    }

    return strstr(haystack, needle);
}

CVB_CHAR* CmscbbStrChr(const CVB_CHAR* s, CVB_CHAR c)
{
    if (s == NULL) {
        tloge("CMSCBB: str s is NULL\n");
        return NULL;
    }

    return strchr(s, (int)c);
}

CVB_UINT32 CmscbbStrlen(const CVB_CHAR* s)
{
    if (s == NULL) {
        tloge("CMSCBB: str s is NULL\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    return (CVB_UINT32)strlen(s);
}

CVB_INT CmscbbStrCmp(const CVB_CHAR* s1, const CVB_CHAR* s2)
{
    if (s1 == NULL || s2 == NULL) {
        tloge("CMSCBB: str s1 or s2 is NULL\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    if (s1 == s2) {
        tloge("CMSCBB: str s1 and s2 are the same str\n");
        return 0;
    }

    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    if (len1 != len2) {
        tlogd("CMSCBB: str s1 and s2 lens are not same\n");
        return -1;
    }

    return strncmp(s1, s2, len1);
}

#if CMSCBB_SUPPORT_FILE
CVB_FILE_HANDLE CmscbbFileOpen(const CVB_CHAR* path, const CVB_CHAR* mode)
{
    (void)path;
    (void)mode;
    return NULL;
}

CVB_SIZE_T CmscbbFileRead(CVB_VOID* ptr, CVB_SIZE_T size, CVB_FILE_HANDLE fp)
{
    (void)ptr;
    (void)size;
    (void)fp;
    return 0;
}

CMSCBB_ERROR_CODE CmscbbFileClose(CVB_FILE_HANDLE fp)
{
    (void)fp;
    return 0;
}

CVB_UINT64 CmscbbFileGetSize(CVB_FILE_HANDLE fp)
{
    (void)fp;
    return 0;
}
#endif /* CMSCBB_SUPPORT_FILE */

#if CMSCBB_ENABLE_LOG
CVB_VOID CmscbbLogPrint(CMSCBB_LOG_TYPE log_level, const CVB_CHAR *filename, CVB_INT line,
                        const CVB_CHAR *function, CMSCBB_ERROR_CODE rc, const CVB_CHAR *log)
{
    (void)log_level;
    (void)filename;
    (void)line;
    (void)function;
    (void)rc;
    (void)log;
}
#endif

CMSCBB_ERROR_CODE CmscbbMdCreateCtx(CMSCBB_CRYPTO_MD_CTX *md_ctx)
{
    if (md_ctx == NULL) {
        tloge("CMSCBB: md create ctx invalid params\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    gt_crypto_md *pmd = NULL;
    CMSCBB_ERROR_CODE ret = CmscbbMalloc((CVB_VOID **)(&pmd), sizeof(gt_crypto_md));
    if (ret != CVB_SUCCESS || pmd == NULL) {
        tloge("CMSCBB: md create ctx malloc failed\n");
        return ret;
    }

    *md_ctx = (CMSCBB_CRYPTO_MD_CTX)pmd;
    return ret;
}

CMSCBB_ERROR_CODE CmscbbMdInit(CMSCBB_CRYPTO_MD_CTX md_ctx, CVB_UINT32 hash_id)
{
    gt_crypto_md *pmd = (gt_crypto_md *)md_ctx;
    if (pmd == NULL) {
        tloge("CMSCBB: md init invalid params\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    int res = SHA256_Init(&(pmd->ctx));
    if (res != CVB_TRUE) {
        tloge("CMSCBB: md init sha failed\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pmd->hash_algo = hash_id;
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbMdUpdate(CMSCBB_CRYPTO_MD_CTX md_ctx, const CVB_BYTE *data, CVB_UINT32 len)
{
    gt_crypto_md *pmd = (gt_crypto_md *)md_ctx;
    bool check_params = (pmd == NULL || data == NULL || len == 0);
    if (check_params) {
        tloge("CMSCBB: md update invalid params");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    int res = SHA256_Update(&(pmd->ctx), (void *)data, (size_t)len);
    if (res != CVB_TRUE) {
        tloge("CMSCBB: md update sha failed\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbMdFinal(CMSCBB_CRYPTO_MD_CTX md_ctx, CVB_BYTE *digest, CVB_UINT32 *len,
                                const CVB_UINT32 *digest_max_len)
{
    gt_crypto_md *pmd = (gt_crypto_md *)md_ctx;
    bool check_params = (pmd == NULL || digest == NULL || len == NULL || digest_max_len == NULL);
    if (check_params) {
        tloge("CMSCBB: md final invalid params\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    *len = SHA256_HASH_LEN;
    int res = SHA256_Final(digest, &(pmd->ctx));
    if (res != CVB_TRUE) {
        tloge("CMSCBB: md final sha failed\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    return CVB_SUCCESS;
}

CVB_VOID CmscbbMdDestoryCtx(CMSCBB_CRYPTO_MD_CTX md_ctx)
{
    gt_crypto_md *pmd = (gt_crypto_md *)md_ctx;
    if (pmd != NULL)
        CmscbbFree(pmd);
}

CMSCBB_ERROR_CODE CmscbbCryptoVerifyCreateCtx(CMSCBB_CRYPTO_VRF_CTX *ctx)
{
    if (ctx == NULL) {
        tloge("CMSCBB: crypto verify create ctx invalid params\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    gt_crypto_vrf *pvrf = NULL;
    CMSCBB_ERROR_CODE ret = CmscbbMalloc((void **)&pvrf, sizeof(gt_crypto_vrf));
    if (ret != CVB_SUCCESS || pvrf == NULL) {
        tloge("CMSCBB: crypto verify create ctx malloc failed\n");
        return ret;
    }

    *ctx = (CMSCBB_CRYPTO_VRF_CTX)pvrf;
    return ret;
}

CMSCBB_ERROR_CODE CmscbbCryptoVerifyInit(CMSCBB_CRYPTO_VRF_CTX vrf_ctx, const CmscbbBigInt *e,
                                         const CmscbbBigInt *n, CVB_UINT32 cmscbb_hashid)
{
    gt_crypto_vrf *pvrf = (gt_crypto_vrf *)vrf_ctx;
    bool check_params = (pvrf == NULL || e == NULL || n == NULL);
    if (check_params) {
        tloge("CMSCBB: crypto verify init invalid params\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pvrf->rsa_key = get_rsa_key(e, n);
    if (pvrf->rsa_key == NULL) {
        tloge("CMSCBB: crypto verify init get rsa key failed\n");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CMSCBB_ERROR_CODE ret = CmscbbMdInit(&(pvrf->md_ctx), cmscbb_hashid);
    if (ret != CVB_SUCCESS) {
        tloge("CMSCBB: crypto verify init md init failed (0x%x)\n", ret);
        put_rsa_key(pvrf);
    }

    return ret;
}

CMSCBB_ERROR_CODE CmscbbCryptoVerifyUpdate(CMSCBB_CRYPTO_VRF_CTX vrf_ctx,
                                           const CVB_BYTE *data, CVB_UINT32 len)
{
    gt_crypto_vrf *pvrf = (gt_crypto_vrf *)vrf_ctx;
    bool check_params = (pvrf == NULL || data == NULL || len == 0);
    if (check_params) {
        tloge("CMSCBB: crypto verify update invalid params\n");
        put_rsa_key(pvrf);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CMSCBB_ERROR_CODE ret = CmscbbMdUpdate(&(pvrf->md_ctx), data, len);
    if (ret != CVB_SUCCESS) {
        tloge("CMSCBB: crypto verify update md update failed (0x%x)\n", ret);
        put_rsa_key(pvrf);
        return ret;
    }

    return ret;
}

CMSCBB_ERROR_CODE CmscbbCryptoVerifyFinal(CMSCBB_CRYPTO_VRF_CTX vrf_ctx, const CVB_BYTE *signature,
                                          CVB_UINT32 len, CVB_INT *r_result)
{
    gt_crypto_vrf *pvrf = (gt_crypto_vrf *)vrf_ctx;
    bool check_params = (pvrf == NULL || pvrf->rsa_key == NULL ||
                         signature == NULL || r_result == NULL);
    if (check_params) {
        tloge("CMSCBB: crypto verify final invalid params\n");
        put_rsa_key(pvrf);
        if (r_result != NULL)
            *r_result = CVB_FALSE;
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CVB_BYTE msg_hash[CMSCBB_MAX_DIGEST_SIZE] = {0};
    CVB_UINT32 hash_len = 0;
    CMSCBB_ERROR_CODE ret = CmscbbMdFinal(&(pvrf->md_ctx), msg_hash, &hash_len, &hash_len);
    if (ret != CVB_SUCCESS) {
        tloge("CMSCBB: crypto verify final md final failed (0x%x)\n", ret);
        put_rsa_key(pvrf);
        *r_result = CVB_FALSE;
        return ret;
    }

    int hash_nid = NID_sha256;
    int res = RSA_verify(hash_nid, msg_hash, hash_len, signature, len, pvrf->rsa_key);
    if (res != CVB_TRUE) {
        tloge("CMSCBB: Soft rsa verify digest failed\n");
        put_rsa_key(pvrf);
        *r_result = CVB_FALSE;
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    put_rsa_key(pvrf);
    *r_result = CVB_TRUE;
    return ret;
}

CVB_VOID CmscbbCryptoVerifyDestroyCtx(CMSCBB_CRYPTO_VRF_CTX vrf_ctx)
{
    gt_crypto_vrf *pvrf = (gt_crypto_vrf *)vrf_ctx;
    if (pvrf != NULL) {
        put_rsa_key(pvrf);
        CmscbbFree(pvrf);
    }
}
