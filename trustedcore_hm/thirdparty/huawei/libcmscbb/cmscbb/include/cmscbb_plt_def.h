/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */

/*
 *    File Name            :     cmscbb_sys_def.h
 *    Brief                :     system function definition File
 *    Author               :     l90006223
 *    Date                 :     2015/01/14 9:03
 */
#ifndef H_CMSCBB_PLT_DEF_H
#define H_CMSCBB_PLT_DEF_H
#include "cmscbb_config.h"
#include "cmscbb_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* --cplusplus */

#ifdef CMSCBB_ENABLE_LOG

/* Define log output level */
#define CMSCBB_LOG_LEVEL_DEBUG 4 /* Output debugging, information, alarms, and error logs */
#define CMSCBB_LOG_LEVEL_INFO 3 /* Output information, alarms, and error logs */
#define CMSCBB_LOG_LEVEL_WARNING 2 /* Output Alarms and error logs */
#define CMSCBB_LOG_LEVEL_ERROR 1 /* Output error Log */
#define CMSCBB_LOG_LEVEL_NONE 0 /* Do not output log */

#ifndef _CMSCBB_LOG_LEVEL_
#define _CMSCBB_LOG_LEVEL_ CMSCBB_LOG_LEVEL_INFO
#endif

/* log type */
typedef enum {
    CMSCBB_LOG_TYPE_ERROR = 0,
    CMSCBB_LOG_TYPE_WARNING = 1,
    CMSCBB_LOG_TYPE_INFO = 2,
    CMSCBB_LOG_TYPE_DEBUG = 3,
} CMSCBB_LOG_TYPE;
#endif /* CMSCBB_ENABLE_LOG */

/*
 * crypto definition
 */
/* sigcbb Digest algorithm definition */
#define	CMSCBB_HASH_UNKONW (-1)
#define	CMSCBB_HASH_SHA256 43
#define	CMSCBB_HASH_SHA384 44
#define	CMSCBB_HASH_SHA512 45

/* SIGCBB algorithm middle-tier context data definition */
typedef void* CMSCBB_CRYPTO_MD_CTX;
typedef void* CMSCBB_CRYPTO_VRF_CTX;

/* Define Maximum summary length */
#ifndef CMSCBB_MAX_DIGEST_SIZE
#define CMSCBB_MAX_DIGEST_SIZE 64
#endif

/* Define the maximum length of encryption */
#ifndef CMSCBB_MAX_CRYPT_SIZE
#define CMSCBB_MAX_CRYPT_SIZE 516
#endif

/* Maximum public key data length */
#ifndef CMSCBB_MAX_PUBKEY_SIZE
#define CMSCBB_MAX_PUBKEY_SIZE (1024 << 8)
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* H_CMSCBB_PLT_DEF_H */
