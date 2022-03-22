/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: TA sevice for privacydata protection
 * Create: 2020-03-01
 */

#include "privacy_protection_common.h"
#include "privacy_protection_syscall.h"
#include "hieps_power.h"
#include "tee_log.h"
#include "string.h"
#include "hisee_seceng.h"

/*
 * power on mspe
 * make sure mspe is powered before use api interface
 * return 0:success, other:fail
 */
uint32_t mspe_poweron(uint32_t cmd, uint32_t id, uint32_t profile)
{
    uint32_t ret;

    if (cmd != PRIP_MSP_POWERON)
        return MSPE_ERRCODE_TEE_PARAMERR;
    ret = hieps_power_on(id, profile);
    if (ret != MSPE_TEE_OK) {
        tloge("prip: mspe power on fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_POWERONERR;
    }

    return MSPE_TEE_OK;
}

/*
 * power off mspe
 * return 0:success, other:fail
 */
uint32_t mspe_poweroff(uint32_t cmd, uint32_t id, uint32_t profile)
{
    uint32_t ret;

    if (cmd != PRIP_MSP_POWEROFF)
        return MSPE_ERRCODE_TEE_PARAMERR;

    ret = hieps_power_off(id, profile);
    if (ret != MSPE_TEE_OK) {
        tloge("prip: mspe power off fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_POWEROFFERR;
    }

    return MSPE_TEE_OK;
}

/*
 * get a fixed-length random number
 * return 0:success, other:fail
 */
uint32_t mspe_rnd_gen_trnd(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint8_t *ptrnd = NULL;
    uint32_t len;

    if (!param || cmd != PRIP_RNG_GEN_TRND)
        return MSPE_ERRCODE_TEE_PARAMERR;

    ptrnd = (uint8_t *)(uintptr_t)param->buf[0].pdata;
    len   = param->buf[0].size;
    ret = hisee_rng_gen_trnd(ptrnd, len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe gen trnd fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_GENTRNDERR;
    }

    return MSPE_TEE_OK;
}

/*
 * get the public and private key pair of sm2
 * return 0:success, other:fail
 */
uint32_t mspe_sm2_gen_key(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_ecc_keypair pkey = {0};

    if (!param || cmd != PRIP_SM2_GEN_KEY)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pkey.curve_id = param->param[ID0];
    pkey.width = param->param[ID1];
    pkey.priv.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    pkey.priv.size = param->buf[ID0].size;
    pkey.pubx.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pkey.pubx.size = param->buf[ID1].size;
    pkey.puby.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pkey.puby.size = param->buf[ID2].size;

    ret = hisee_sm2_gen_key(&pkey);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe gen sm2 key fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM2GETKEYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * use sm2 to encrypt data
 * return 0:success, other:fail
 */
uint32_t mspe_sm2_encrypt(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_ecc_pubkey pkey = {0};
    const uint8_t *pin = NULL;
    uint32_t in_len;
    uint8_t *pout = NULL;
    uint32_t *pout_len = NULL;

    if (!param || cmd != PRIP_SM2_ENCRYPT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pkey.curve_id = param->param[ID0];
    pkey.width = param->param[ID1];
    pkey.pubx.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    pkey.pubx.size = param->buf[ID0].size;
    pkey.puby.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pkey.puby.size = param->buf[ID1].size;
    pin = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    in_len = param->buf[ID2].size;
    pout = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    pout_len = (uint32_t *)(uintptr_t)param->buf[ID4].pdata;

    ret = hisee_sm2_encrypt(&pkey, pin, in_len, pout, pout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm2 encrypt fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM2ENCRYPTERR;
    }

    return MSPE_TEE_OK;
}

/*
 * use sm2 to decrypt data
 * return 0:success, other:fail
 */
uint32_t mspe_sm2_decrypt(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_ecc_privkey pkey = {0};
    const uint8_t *pin = NULL;
    uint32_t in_len;
    uint8_t *pout = NULL;
    uint32_t *pout_len = NULL;

    if (!param || cmd != PRIP_SM2_DECRYPT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pkey.curve_id = param->param[ID0];
    pkey.width = param->param[ID1];
    pkey.priv.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    pkey.priv.size = param->buf[ID0].size;
    pkey.width = param->param[ID1];
    pin = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    in_len = param->buf[ID1].size;
    pout = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pout_len = (uint32_t *)(uintptr_t)param->buf[ID3].pdata;

    ret = hisee_sm2_decrypt(&pkey, pin, in_len, pout, pout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm2 decrypt fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM2DECRYPTERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm3 hash initialization interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm3_hash_init(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_hash_user_ctx *pctx = NULL;
    uint32_t alg_type;

    if (!param || cmd != PRIP_SM3_HASH_INIT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    alg_type = param->param[ID0];
    pctx = (struct hisee_hash_user_ctx *)(uintptr_t)param->buf[ID0].pdata;

    ret = hisee_hash_init(pctx, alg_type);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm3 hash init fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM3INITERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm3 hash updata interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm3_hash_update(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_hash_user_ctx *pctx = NULL;
    uint8_t *pdin = NULL;
    uint32_t din_len;

    if (!param || cmd != PRIP_SM3_HASH_UPDATE)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pctx = (struct hisee_hash_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    pdin = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    din_len = param->buf[ID1].size;

    ret = hisee_hash_update(pctx, pdin, din_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm3 hash update fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM3UPDATEERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm3 hash dofinal interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm3_hash_dofinal(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_hash_user_ctx *pctx = NULL;
    uint8_t *pdin = NULL;
    uint32_t din_len;
    uint8_t *pdout = NULL;
    uint32_t *pdout_len = NULL;

    if (!param || cmd != PRIP_SM3_HASH_DOFINAL)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pctx = (struct hisee_hash_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    pdin = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    din_len = param->buf[ID1].size;
    pdout = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pdout_len = (uint32_t *)(uintptr_t)param->buf[ID3].pdata;

    ret = hisee_hash_dofinal(pctx, pdin, din_len, pdout, pdout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm3 hash dofinal fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM3DOFINALERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm3 hash sigle interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm3_hash_sigle(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t alg;
    uint8_t *pdin = NULL;
    uint32_t din_len;
    uint8_t *pdout = NULL;
    uint32_t *pdout_len = NULL;

    if (!param || cmd != PRIP_SM3_HASH_SIGLE)
        return MSPE_ERRCODE_TEE_PARAMERR;

    alg = param->param[ID0];
    pdin = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    din_len = param->buf[ID0].size;
    pdout = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pdout_len = (uint32_t *)(uintptr_t)param->buf[ID2].pdata;

    ret = hisee_hash_single(alg, pdin, din_len, pdout, pdout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm3 hash sigle fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM3SIGLEERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm4 set key interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm4_set_key(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm4_user_ctx *pctx = NULL;
    uint32_t key_type;
    uint8_t *pkey = NULL;
    uint32_t key_len;

    if (!param || cmd != PRIP_SM4_SET_KEY)
        return MSPE_ERRCODE_TEE_PARAMERR;

    key_type = param->param[ID0];
    pctx = (struct hisee_sm4_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    pkey = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    key_len = param->buf[ID1].size;

    ret = hisee_sm4_set_key(pctx, key_type, pkey, key_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm4 set key fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM4SETKEYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm4 set iv interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm4_set_iv(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm4_user_ctx *pctx = NULL;
    uint8_t *piv = NULL;
    uint32_t iv_len;

    if (!param || cmd != PRIP_SM4_SET_IV)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pctx = (struct hisee_sm4_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    piv = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    iv_len = param->buf[ID1].size;

    ret = hisee_sm4_set_iv(pctx, piv, iv_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm4 set iv fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM4SETKIVERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm4 initialization interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm4_init(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm4_user_ctx *pctx = NULL;
    uint32_t direction;
    uint32_t mode;
    uint32_t padding_type;

    if (!param || cmd != PRIP_SM4_INIT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    direction = param->param[ID0];
    mode = param->param[ID1];
    padding_type = param->param[ID2];
    pctx = (struct hisee_sm4_user_ctx *)(uintptr_t)param->buf[ID0].pdata;

    ret = hisee_sm4_init(pctx, direction, mode, padding_type);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm4 init fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM4INITERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm4 update interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm4_update(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm4_user_ctx *pctx = NULL;
    uint8_t *pdin = NULL;
    uint32_t din_len;
    uint8_t *pdout = NULL;
    uint32_t *pdout_len = NULL;

    if (!param || cmd != PRIP_SM4_UPDATE)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pctx = (struct hisee_sm4_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    pdin = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    din_len = param->buf[ID1].size;
    pdout = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pdout_len = (uint32_t *)(uintptr_t)param->buf[ID3].pdata;

    ret = hisee_sm4_update(pctx, pdin, din_len, pdout, pdout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm4 update fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM4UPDATEERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm4 dofinal interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm4_dofinal(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm4_user_ctx *pctx = NULL;
    uint8_t *pdin = NULL;
    uint32_t din_len;
    uint8_t *pdout = NULL;
    uint32_t *pdout_len = NULL;

    if (!param || cmd != PRIP_SM4_DOFINAL)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pctx = (struct hisee_sm4_user_ctx *)(uintptr_t)param->buf[ID0].pdata;
    pdin = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    din_len = param->buf[ID1].size;
    pdout = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pdout_len = (uint32_t *)(uintptr_t)param->buf[ID3].pdata;

    ret = hisee_sm4_dofinal(pctx, pdin, din_len, pdout, pdout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm4 dofinal fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM4DOFINALERR;
    }

    return MSPE_TEE_OK;
}

/*
 * mk Key derivation interface
 * return 0:success, other:fail
 */
uint32_t mspe_km_derive_kdr(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint8_t *pdin = NULL;
    uint32_t din_len;
    uint8_t *pdout = NULL;
    uint32_t *pdout_len = NULL;

    if (!param || cmd != PRIP_KM_DERIVE_KDR)
        return MSPE_ERRCODE_TEE_PARAMERR;

    pdin = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    din_len = param->buf[ID0].size;
    pdout = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pdout_len = (uint32_t *)(uintptr_t)param->buf[ID2].pdata;

    ret = hisee_pri_protect_derive_kdr(pdin, din_len, pdout, pdout_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe km derive key fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_KMDERIVEKEYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 sign interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_sign(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t hash_type;
    struct hisee_sm9_user_private_key sk = {0};
    struct hisee_sm9_public_key mpk = {0};
    struct basic_data pri_key = {0};
    struct basic_data ppub = {0};
    struct basic_data pre_data = {0};
    uint8_t *data = NULL;
    uint32_t data_len;
    uint8_t *sign = NULL;
    uint32_t *sign_len = NULL;

    if (!param || cmd != PRIP_SM9_SIGN)
        return MSPE_ERRCODE_TEE_PARAMERR;

    hash_type = param->param[ID0];
    mpk.pairing = param->param[ID1];
    pri_key.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    pri_key.size = param->buf[ID0].size;
    sk.puser_key = &pri_key;
    ppub.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    ppub.size = param->buf[ID1].size;
    mpk.ppub = &ppub;
    pre_data.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pre_data.size = param->buf[ID2].size;
    mpk.ppre_data = &pre_data;
    data = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    data_len = param->buf[ID3].size;
    sign = (uint8_t *)(uintptr_t)param->buf[ID4].pdata;
    sign_len = (uint32_t *)(uintptr_t)param->buf[ID5].pdata;

    ret = hisee_sm9_sign(hash_type, &sk, &mpk, data, data_len, sign, sign_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 sign fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9SIGNERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 verify interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_verify(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t hash_type;
    struct hisee_sm9_public_key mpk = {0};
    struct basic_data id = {0};
    struct basic_data ppub = {0};
    struct basic_data pre_data = {0};
    uint8_t *data = NULL;
    uint32_t data_len;
    uint8_t *sign = NULL;
    uint32_t sign_len;

    if (!param || cmd != PRIP_SM9_VERIFY)
        return MSPE_ERRCODE_TEE_PARAMERR;

    hash_type   = param->param[ID0];
    mpk.pairing = param->param[ID1];
    ppub.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    ppub.size = param->buf[ID0].size;
    mpk.ppub = &ppub;
    pre_data.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pre_data.size = param->buf[ID1].size;
    mpk.ppre_data = &pre_data;
    id.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    id.size = param->buf[ID2].size;
    data = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    data_len = param->buf[ID3].size;
    sign = (uint8_t *)(uintptr_t)param->buf[ID4].pdata;
    sign_len = param->buf[ID4].size;
    ret = hisee_sm9_verify(hash_type, &mpk, &id, data, data_len, sign, sign_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 verify fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9VERIFYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 encrypt interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_encrypt(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm9_en_para en_type = {0};
    struct hisee_sm9_public_key mpk = {0};
    struct basic_data id = {0};
    struct basic_data ppub = {0};
    struct basic_data pre_data = {0};
    struct basic_data iv = {0};
    uint8_t *in = NULL;
    uint32_t in_len;
    uint8_t *out = NULL;
    uint32_t *out_len = NULL;

    if (!param || cmd != PRIP_SM9_ENCRYPT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    en_type.sm9_en_type = param->param[ID0];
    mpk.pairing = param->param[ID1];
    if ((uint8_t *)(uintptr_t)param->buf[ID0].pdata) {
        iv.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
        iv.size = param->buf[ID0].size;
        en_type.iv = &iv;
    } else {
        en_type.iv = NULL;
    }
    ppub.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    ppub.size = param->buf[ID1].size;
    pre_data.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    pre_data.size = param->buf[ID2].size;
    mpk.ppub = &ppub;
    mpk.ppre_data = &pre_data;
    id.pdata = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    id.size = param->buf[ID3].size;
    in = (uint8_t *)(uintptr_t)param->buf[ID4].pdata;
    in_len = param->buf[ID4].size;
    out = (uint8_t *)(uintptr_t)param->buf[ID5].pdata;
    out_len = (uint32_t *)(uintptr_t)param->buf[ID6].pdata;

    ret = hisee_sm9_encrypt(&en_type, &mpk, &id, in, in_len, out, out_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 encrypt fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9ENCRYPTERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 decrypt interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_decrypt(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    struct hisee_sm9_en_para en_type = {0};
    struct hisee_sm9_user_private_key sk = {0};
    uint32_t curve_id;
    struct basic_data id = {0};
    struct basic_data pri_key = {0};
    struct basic_data iv = {0};
    uint8_t *in = NULL;
    uint32_t in_len;
    uint8_t *out = NULL;
    uint32_t *out_len = NULL;

    if (!param || cmd != PRIP_SM9_DECRYPT)
        return MSPE_ERRCODE_TEE_PARAMERR;

    en_type.sm9_en_type = param->param[ID0];
    curve_id = param->param[ID1];
    if ((uint8_t *)(uintptr_t)param->buf[ID0].pdata) {
        iv.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
        iv.size = param->buf[ID0].size;
        en_type.iv = &iv;
    } else {
        en_type.iv = NULL;
    }
    pri_key.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pri_key.size = param->buf[ID1].size;
    sk.puser_key = &pri_key;
    id.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    id.size = param->buf[ID2].size;
    in = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    in_len = param->buf[ID3].size;
    out = (uint8_t *)(uintptr_t)param->buf[ID4].pdata;
    out_len = (uint32_t *)(uintptr_t)param->buf[ID5].pdata;

    ret = hisee_sm9_decrypt(&en_type, &sk, curve_id, &id, in, in_len, out, out_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 decrypt fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9DECRYPTERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 wrap key interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_wrap_key(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t hash_type;
    struct hisee_sm9_public_key mpk = {0};
    struct basic_data id = {0};
    struct basic_data ppub = {0};
    struct basic_data pre_data = {0};
    uint8_t *key = NULL;
    uint32_t key_len;
    uint8_t *enced_key = NULL;
    uint32_t *enced_len = NULL;

    if (!param || cmd != PRIP_SM9_WRAP_KEY)
        return MSPE_ERRCODE_TEE_PARAMERR;

    hash_type = param->param[ID0];
    mpk.pairing = param->param[ID1];
    ppub.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    ppub.size = param->buf[ID0].size;
    pre_data.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    pre_data.size = param->buf[ID1].size;
    mpk.ppub = &ppub;
    mpk.ppre_data = &pre_data;
    id.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    id.size = param->buf[ID2].size;
    key = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    key_len = param->buf[ID3].size;
    enced_key = (uint8_t *)(uintptr_t)param->buf[ID4].pdata;
    enced_len = (uint32_t *)(uintptr_t)param->buf[ID5].pdata;

    ret = hisee_sm9_wrap_key(hash_type, &mpk, &id, key, key_len, enced_key, enced_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 wrap key fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9WRAPKEYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 unwrap key interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_unwrap_key(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t hash_type;
    struct hisee_sm9_user_private_key sk = {0};
    uint32_t curve_id;
    struct basic_data id = {0};
    struct basic_data pri_key = {0};
    uint8_t *key = NULL;
    uint32_t key_len;
    uint8_t *enced_key = NULL;
    uint32_t enced_len;

    if (!param || cmd != PRIP_SM9_UNWRAP_KEY)
        return MSPE_ERRCODE_TEE_PARAMERR;

    hash_type = param->param[ID0];
    curve_id = param->param[ID1];
    pri_key.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    pri_key.size = param->buf[ID0].size;
    sk.puser_key = &pri_key;
    id.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    id.size = param->buf[ID1].size;
    key = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    key_len = param->buf[ID2].size;
    enced_key = (uint8_t *)(uintptr_t)param->buf[ID3].pdata;
    enced_len = param->buf[ID3].size;

    ret = hisee_sm9_unwrap_key(hash_type, &sk, curve_id, &id, key, key_len, enced_key, enced_len);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 unwrap key fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9UNWRAPKEYERR;
    }

    return MSPE_TEE_OK;
}

/*
 * sm9 get pre-calculated data interface
 * return 0:success, other:fail
 */
uint32_t mspe_sm9_pre_data(uint32_t cmd, const struct prip_drv_param *param)
{
    int32_t ret;
    uint32_t id;
    struct basic_data ppubs = {0};
    struct basic_data ppube = {0};
    struct basic_data ppre_data = {0};

    if (!param || cmd != PRIP_SM9_PRE_DATA)
        return MSPE_ERRCODE_TEE_PARAMERR;

    id = param->param[ID0];
    ppubs.pdata = (uint8_t *)(uintptr_t)param->buf[ID0].pdata;
    ppubs.size = param->buf[ID0].size;
    ppube.pdata = (uint8_t *)(uintptr_t)param->buf[ID1].pdata;
    ppube.size = param->buf[ID1].size;
    ppre_data.pdata = (uint8_t *)(uintptr_t)param->buf[ID2].pdata;
    ppre_data.size = param->buf[ID2].size;

    ret = hisee_sm9_precompute_data(id, &ppubs, &ppube, &ppre_data);
    if (ret != BSP_RET_OK) {
        tloge("prip: mspe sm9 pre compute data fail! ret = 0x%x\n", ret);
        return MSPE_ERRCODE_TEE_SM9PREDATAERR;
    }

    return MSPE_TEE_OK;
}

