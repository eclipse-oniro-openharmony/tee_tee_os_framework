/****************************************************************************//**
 * @file   : run_func.h
 * @brief  : function data needed by ipc
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/19
 * @author : m00475438
 * @note   :
********************************************************************************/
#ifndef __RUN_FUNC_H__
#define __RUN_FUNC_H__

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
typedef enum ipc_func_id_enum {
    FUNC_HAL_SM2_GET_A = 0x0,
    /* cipher */
    FUNC_API_CIPHER_INIT,
    FUNC_API_CIPHER_UPDATE,
    FUNC_API_CIPHER_UPDATE_BLOCKS,
    FUNC_API_CIPHER_UPDATE_VIDEO,
    FUNC_API_CIPHER_DOFINAL,
    /* hash */
    FUNC_API_HASH,
    FUNC_API_HASH_INIT,
    FUNC_API_HASH_UPDATE,
    FUNC_API_HASH_DOFINAL,
    /* hmac */
    FUNC_API_HMAC,
    FUNC_API_HMAC_INIT,
    FUNC_API_HMAC_UPDATE,
    FUNC_API_HMAC_DOFINAL,
    FUNC_API_HMAC_LICENCE,
    /* mac */
    FUNC_API_MAC,
    FUNC_API_MAC_INIT,
    FUNC_API_MAC_UPDATE,
    FUNC_API_MAC_DOFINAL,
    /* km */
    FUNC_API_ENCRYPT_CLIENT_PRIVK,
    FUNC_API_DECRYPT_LICENCE_HMACK,
    FUNC_API_DECRYPT_SESSION_KEY,
    FUNC_API_DECRYPT_CEK,

    /* PKE */
    FUNC_API_PKE_GENKEY,
    FUNC_API_PKE_ENCRYPT,
    FUNC_API_PKE_DECRYPT,
    FUNC_API_PKE_SIGN,
    FUNC_API_PKE_VERIFY,
    FUNC_API_RSA_BMMUL,
    FUNC_API_SM2_ENCRYPT,
    FUNC_API_SM2_DECRYPT,
    FUNC_API_SM2_SIGN,
    FUNC_API_SM2_VERIFY,
    FUNC_API_SM2_DIGEST_SIGN,
    FUNC_API_SM2_DIGEST_VERIFY,
    FUNC_API_SM2_GEN_KEYPAIR,

    /* MMU */
    FUNC_PAL_MMU_ENABLE,
    FUNC_PAL_MMU_DISABLE,

    /* for autotest */
#ifdef FEATURE_AUTOTEST
    FUNC_AUOTEST_MAIN,
#endif /* FEATURE_AUTOTEST */

    FUNC_ID_MAX
} func_id_e;

typedef enum func_params_enum {
    FUNC_PARAMS_0 = 0x0,
    FUNC_PARAMS_1,
    FUNC_PARAMS_2,
    FUNC_PARAMS_3,
    FUNC_PARAMS_4,
    FUNC_PARAMS_5, /* specification require not exceed 5 */
    FUNC_PARAMS_6,
    FUNC_PARAMS_7,
    FUNC_PARAMS_MAX
} func_params_e;

/**
 * @brief run function header
*/
typedef struct func_header_stru {
    u32       timestamp;
    err_bsp_t ret;
    u32       id;
} func_header_s;

/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
err_bsp_t run_func(u8 *pack, u32 len);

#endif /* __RUN_FUNC_H__ */
