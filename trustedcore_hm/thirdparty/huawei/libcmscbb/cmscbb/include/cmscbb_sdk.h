/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */

/*
 * File Name          : cmscbb_plt_proxy.h
 * Brief              : Realization of function definition by external implementation platform class and algorithm class
 * Author             : t00307193
 * Creation Date      : 2015/05/30 17:34:201
 * Note               : Only  "Embedded version " is required for CMSCBB users to use this header file
 *      Date time           Author        Description
 *      2015/05/30 17:34    t00307193     new
 */
#ifndef H_CMSCBB_SDK_H
#define H_CMSCBB_SDK_H
#include "cmscbb_config.h"
#include "cmscbb_plt_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Prototype    : CmscbbMalloc
 * Description  : Implementing Memory Allocations
 * Params
 *   [IN] ppByte: Pointer to the allocated space
 *   [IN] size: Bytes to allocate
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:34  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMalloc(CVB_VOID** ppByte, CVB_SIZE_T size);

/*
 * Prototype    : CmscbbFree
 * Description  : Implementing Memory Release
 * Params
 *   [IN] ptr: Previously allocated memory block to be freed
 * Return Value : CVB_VOID
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_VOID CmscbbFree(CVB_VOID* ptr);

/*
 * Prototype    : CmscbbMemCmp
 * Description  : Implementing Memory comparisons
 * Params
 *   [IN] s1: First buffer
 *   [IN] s2: Second buffer
 *   [IN] n: Number of characters to compare
 * Return Value : int
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_INT CmscbbMemCmp(const CVB_VOID* s1, const CVB_VOID* s2, CVB_SIZE_T n);

#if CMSCBB_WITHOUT_SECUREC == 1

#ifndef errno_t
typedef CVB_INT errno_t;
#endif

/*
 * In order to adapt the configuration of the different product lines
 * to the three-party library, here cmscbb defines the interfaces that
 * are needed, and these functions are not encapsulated by Huawei security
 * functions or extern references. Here, the product line can adapt the security
 * function itself or a custom underlying implementation.
*/
/* memset function */
errno_t memset_s(void* dest, size_t destMax, int c, size_t count);

/* memcpy function */
errno_t memcpy_s(void* dest, size_t destMax, const void* src, size_t count);

/* strcpy */
errno_t strcpy_s(char* strDest, size_t destMax, const char* strSrc);

/* strcat */
errno_t strcat_s(char* strDest, size_t destMax, const char* strSrc);

int vsnprintf_s(char* strDest, size_t destMax, size_t count, const char* format, va_list arglist);

#endif

/*
 * Prototype    : CmscbbStrNCmp
 * Description  : Implements string comparisons, specifying the length of the comparison
 * Params
 *   [IN] s1: Null-terminated strings to compare
 *   [IN] s2: Null-terminated strings to compare
 *   [IN] n: Number of characters to compare
 * Return Value : int
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_INT CmscbbStrNCmp(const CVB_CHAR* s1, const CVB_CHAR* s2, CVB_SIZE_T n);

/*
 * Prototype    : CmscbbStrStr
 * Description  : Implement string Search
 * Params
 *   [IN] haystack: A pointer to the null-terminated string to search
 *   [IN] needle: A pointer to the substring to search for
 * Return Value : const char*
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
const CVB_CHAR* CmscbbStrStr(const CVB_CHAR* haystack, const CVB_CHAR* needle);

/*
 * Prototype    : CmscbbStrChr
 * Description  : Implement string Search
 * Params
 *   [IN] s: Null-terminated source string
 *   [IN] c: Character to be located
 * Return Value : char*
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_CHAR* CmscbbStrChr(const CVB_CHAR* s, CVB_CHAR c);

/*
 * Prototype    : CmscbbStrlen
 * Description  : Implementation computes string length
 * Params
 *   [IN] s: Null-terminated string
 * Return Value : CVB_SIZE_T
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_UINT32 CmscbbStrlen(const CVB_CHAR* s);

/*
 * Prototype    : CmscbbStrCmp
 * Description  : Implementing string Comparisons
 * Params
 *   [IN] s1: Null-terminated strings to compare
 *   [IN] s2: Null-terminated strings to compare
 * Return Value : int
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:38  t00307193  Create
 */
CVB_INT CmscbbStrCmp(const CVB_CHAR* s1, const CVB_CHAR* s2);

#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbFileOpen
 * Description  : Implement File Open
 * Params
 *   [IN] path: File name
 *   [IN] mode: Kind of access that's enabled
 * Return Value : CVB_FILE_HANDLE
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:39  t00307193  Create
 */
CVB_FILE_HANDLE CmscbbFileOpen(const CVB_CHAR* path, const CVB_CHAR* mode);

/*
 * Prototype    : CmscbbFileRead
 * Description  : Implementing file Reads
 * Params
 *   [IN] ptr: Storage location for data
 *   [IN] size: Item size in bytes
 *   [IN] fp: Pointer to FILE structure
 * Return Value : CVB_UINT32
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:39  t00307193  Create
 */
CVB_SIZE_T CmscbbFileRead(CVB_VOID* ptr, CVB_SIZE_T size, CVB_FILE_HANDLE fp);

/*
 * Prototype    : CmscbbFileClose
 * Description  : Implement file shutdown
 * Params
 *   [IN] fp: Pointer to FILE structure
 * Return Value : int
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:39  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbFileClose(CVB_FILE_HANDLE fp);

/*
 * Prototype    : CmscbbFileGetSize
 * Description  : Achieve get file length
 * Params
 *   [IN] fp: Pointer to FILE structure
 * Return Value : CVB_INT64
 * History      
 *   Date              Author     Modification
 *   2015/05/30 17:39  t00307193  Create
 */
CVB_UINT64 CmscbbFileGetSize(CVB_FILE_HANDLE fp);
#endif /* CMSCBB_SUPPORT_FILE */

#if CMSCBB_ENABLE_LOG
/*
 * Prototype    : CmscbbLogPrint
 * Description  : Record log
 * Params
 *   [IN] log_level: Log level
 *   [IN] filename: file that produces the log
 *   [IN] line: Line number that produces the log
 *   [IN] function: function that produces the log
 *   [IN] rc: error id
 *   [IN] log: log String
 * Return Value : CVB_VOID
 * History      
 *   Date              Author     Modification
 *   2016/08/15 15:41  t00307193  Create
 */
CVB_VOID CmscbbLogPrint(CMSCBB_LOG_TYPE log_level, const CVB_CHAR* filename, CVB_INT line, const CVB_CHAR* function, CMSCBB_ERROR_CODE rc, const CVB_CHAR* log);
#endif

/*
 * Prototype    : CmscbbMdCreateCtx
 * Description  : Implementation creation Summary context
 * Params
 *   [OUT] md_ctx: return Summary context
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:28  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMdCreateCtx(CMSCBB_CRYPTO_MD_CTX* md_ctx);

/*
 * Prototype    : CmscbbMdInit
 * Description  : Implementation initialization Summary
 * Params
 *   [IN] md_ctx: Summary context
 *   [IN] hash_id: digest ID
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:28  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMdInit(CMSCBB_CRYPTO_MD_CTX md_ctx, CVB_UINT32 hash_id);

/*
 * Prototype    : CmscbbMdUpdate
 * Description  : The calculation of the original text by the realization abstract
 * Params
 *   [IN] md_ctx: Summary context
 *   [IN] data: Original data
 *   [IN] len: Original data length
 * Return Value : CMSCBB_ERROR_CODE
 * Remarks      : Requirements can be segmented to calculate the summary
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:28  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMdUpdate(CMSCBB_CRYPTO_MD_CTX md_ctx, const CVB_BYTE* data, CVB_UINT32 len);

/*
 * Prototype    : CmscbbMdFinal
 * Description  : Implementation gets the final summary result
 * Params
 *   [IN] md_ctx: Summary context
 *   [OUT] digest: digest
 *   [OUT] len: digest length
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:28  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMdFinal(CMSCBB_CRYPTO_MD_CTX md_ctx, CVB_BYTE* digest, CVB_UINT32* len, const CVB_UINT32* digestMaxLen);

/*
 * Prototype    : CmscbbMdDestoryCtx
 * Description  : destory Summary context
 * Params
 *   [IN] md_ctx: Summary context
 * Return Value : CVB_VOID
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CVB_VOID CmscbbMdDestoryCtx(CMSCBB_CRYPTO_MD_CTX md_ctx);

/*
 * Prototype    : CmscbbCryptoVerifyCreateCtx
 * Description  : create crypto validation context
 * Params
 *   [OUT] ctx: return crypto validation context
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCryptoVerifyCreateCtx(CMSCBB_CRYPTO_VRF_CTX* ctx);

/*
 * Prototype    : CmscbbCryptoVerifyInit
 * Description  : init RSAValidation context
 * Params
 *   [IN] vrf_ctx: RSAValidation context
 *   [IN] e: E Value of Public key
 *   [IN] n: n Value of Public key
 *   [IN] cmscbb_hashid: hash id
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCryptoVerifyInit(CMSCBB_CRYPTO_VRF_CTX vrf_ctx, const CmscbbBigInt* e, const CmscbbBigInt* n, CVB_UINT32 cmscbb_hashid);

/*
 * Prototype    : CmscbbCryptoVerifyUpdate
 * Description  : Implementing RSA Validation calculations
 * Params
 *   [IN] vrf_ctx: RSAValidation context
 *   [IN] data: RSASignature data
 *   [IN] len: RSAData length
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCryptoVerifyUpdate(CMSCBB_CRYPTO_VRF_CTX vrf_ctx, const CVB_BYTE* data, CVB_UINT32 len);

/*
 * Prototype    : CmscbbCryptoVerifyFinal
 * Description  : get RSAValidation results
 * Params
 *   [IN] vrf_ctx: RSAValidation context
 *   [IN] signature: RSASignature data
 *   [IN] len: RSAData length
 *   [OUT] r_result: return Validation results
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCryptoVerifyFinal(CMSCBB_CRYPTO_VRF_CTX vrf_ctx, const CVB_BYTE* signature, CVB_UINT32 len, CVB_INT* r_result);

/*
 * Prototype    : CmscbbCryptoVerifyDestroyCtx
 * Description  : destroy RSAValidation context
 * Params
 *   [IN] vrf_ctx: RSAValidation context
 * Return Value : CVB_VOID
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:29  t00307193  Create
 */
CVB_VOID CmscbbCryptoVerifyDestroyCtx(CMSCBB_CRYPTO_VRF_CTX vrf_ctx);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* H_CMSCBB_SDK_H */
