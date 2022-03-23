/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_DEF_H
#define H_CMSCBB_DEF_H
#include "cmscbb_cms_vrf.h"
#include "cmscbb_x509_def.h"

#define CVB_STATIC static

/*
 * data for verify process
 * NOTE: digestCtx & vrfCtx should not both valid.
 */
typedef struct cmscbb_verify_digest_info_st {
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    CMSCBB_CRYPTO_MD_CTX digestCtx; /* Hash handler, for verifying cms with signed attribute */
    CMSCBB_AOIDS nDigestAlgID;  /* Hash algorithm id */
    CVB_BYTE pbDigest[CMSCBB_MAX_DIGEST_SIZE]; /* hash value in cms */
    CVB_UINT32 nDigestSize; /* hash length */
#endif
#if CMSCBB_SUPPORT_NO_SIGNED_ATTR
    CMSCBB_CRYPTO_VRF_CTX vrfCtx;   /* rsa crypt hander, for verifying cms with signed attribute */
    CVB_BYTE pbSignature[CMSCBB_MAX_CRYPT_SIZE];  /* rsa signature value */
    CVB_UINT32 nSignature;  /* rsa signature length */
#endif
} CMSCBB_VERIFY_DIGEST_INFO;
DECLARE_LIST_OF(CMSCBB_VERIFY_DIGEST_INFO);

typedef struct cmscbb_verify_process_st {
    LIST_OF(CMSCBB_VERIFY_DIGEST_INFO) md_info_list;
} CMSCBB_VERIFY_PROCESS;

/* data for verify context */
#define RESERV_SIZE_4 4
#define RESERV_SIZE_64 64
typedef struct cmscbb_vrf_ctx_st {
    CVB_SIZE_T st_size;

#if (CMSCBB_SUPPORT_PEM || CMSCBB_CACHE_ASN_DATA)
    CMSCBB_LIST_DUMMY raw_set;
#endif
    CVB_BOOL crl_frozen;    /* can add new crl */

    CVB_VOID* pki_ctx; /* PKI context */
    CMSCBB_VERIFY_PROCESS vrf_proc; /* data for verify process */
    CVB_BYTE resv0[RESERV_SIZE_4];
    CVB_TIME_T base_time;   /* base time, mostly it should be the timestamp from CMS */
    CMSCBB_ERROR_CODE last_err; /* the last error */
    CVB_INT curr_depth;  /* current depth of certificate tree */
#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
    CmscbbSerialNum tsa_cert_sn;
#endif
    CVB_BYTE resv[RESERV_SIZE_64];  /* reserve data for structure upgrade */
} CMSCBB_VRF;

#endif /* H_CMSCBB_DEF_H */

