/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee sys cipher
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "sys_cipher.h"

#define SM2_DECRYPT_ENC_ZERO 0x04

/*************************** Internal Structure Definition *******************/
/** \addtogroup      symc */
/** @{ */ /** <!-- [mpi] */

/** @} */ /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      symc */
/** @{ */ /** <!-- [mpi] */

hi_s32 sys_symc_create(hi_u32 *hd, hi_cipher_type type)
{
    hi_s32 ret;
    symc_create_t create = { 0 };

    hi_dbg_func_enter();

    ret = memset_s(&create, sizeof(create), 0, sizeof(create));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    create.type = type;
    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_CREATEHANDLE, &create);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *hd = create.id;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_symc_destroy(hi_u32 id)
{
    symc_destroy_t destroy = { 0 };
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&destroy, sizeof(destroy), 0, sizeof(destroy));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    destroy.id = id;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_DESTROYHANDLE, &destroy);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_symc_get_keyslot_handle(hi_handle cipher,  hi_handle *keyslot)
{
    symc_keyslot_t get_keyslot;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&get_keyslot, sizeof(get_keyslot), 0, sizeof(get_keyslot));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    get_keyslot.cipher  = cipher;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_GET_KEYSLOT, &get_keyslot);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }
    *keyslot = get_keyslot.keyslot;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_symc_config(hi_u32 id,
                       hi_cipher_alg alg,
                       hi_cipher_work_mode enWorkMode,
                       hi_cipher_bit_width enBitWidth,
                       hi_cipher_key_length key_len,
                       const hi_u8 *iv, hi_u32 ivlen, hi_u32 iv_usage,
                       hi_mem_handle aad, hi_u32 alen, hi_u32 tlen)
{
    symc_config_t config;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&config, sizeof(config), 0, sizeof(config));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    config.id = id;
    config.alg = alg;
    config.mode = enWorkMode;
    config.klen = key_len;
    config.iv_usage = iv_usage;
    config.aad.mem_handle = aad.mem_handle;
    config.aad.addr_offset = aad.addr_offset;
    config.alen = alen;
    config.tlen = tlen;
    config.ivlen = ivlen;
    config.width = enBitWidth;

    hi_log_dbg("iv len %d, key_len 0x%x\n", ivlen, key_len);

    if (iv != HI_NULL) {
        ret = memcpy_s(config.iv, sizeof(config.iv), iv, ivlen);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(memcpy_s, ret);
            return ret;
        }
    }

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_CONFIGHANDLE, &config);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_symc_get_config(hi_u32 id, hi_cipher_ctrl *ctrl)
{
    symc_get_config_t get_config;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&get_config, sizeof(get_config), 0, sizeof(get_config));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    get_config.id = id;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_GET_CONFIG, &get_config);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    ret = memcpy_s(ctrl, sizeof(hi_cipher_ctrl), &get_config.ctrl, sizeof(hi_cipher_ctrl));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_symc_crypto(hi_u32 id, hi_mem_handle input,
                       hi_mem_handle output, hi_u32 length,
                       hi_u32 operation, hi_tee_cipher_data_dir data_dir)
{
    symc_encrypt_t encrypt;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&encrypt, sizeof(encrypt), 0, sizeof(encrypt));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    encrypt.id = id;
    encrypt.input = input;
    encrypt.output = output;
    encrypt.length = length;
    encrypt.operation = operation;
    encrypt.data_dir = data_dir;
    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_ENCRYPT, &encrypt);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_MULTI_CIPHER_SUPPORT
hi_s32 sys_symc_crypto_multi(hi_u32 id, const hi_cipher_data *pkg, hi_u32 pkg_num,
                             hi_u32 operation, hi_tee_cipher_data_dir data_dir)
{
    symc_encrypt_multi_t encrypt_multi;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&encrypt_multi, sizeof(encrypt_multi), 0, sizeof(encrypt_multi));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    encrypt_multi.id = id;
    ADDR_VIA(encrypt_multi.pkg) = (hi_cipher_data *)pkg;
    encrypt_multi.pkg_num = pkg_num;
    encrypt_multi.operation = operation;
    encrypt_multi.data_dir = data_dir;
    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_ENCRYPTMULTI, &encrypt_multi);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

#ifdef HI_PRODUCT_CBC_MAC_SUPPORT
hi_s32 sys_symc_aes_cmac(hi_u32 id, hi_u8 *in, hi_u32 inlen, hi_u8 *mac, hi_u32 last)
{
    symc_cmac_t cmac;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = memset_s(&cmac, sizeof(cmac), 0, sizeof(cmac));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    cmac.id = id;
    ADDR_VIA(cmac.in) = in;
    cmac.inlen = inlen;
    cmac.last = last;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_CMAC, &cmac);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    if (last == HI_TRUE) {
        ret = memcpy_s(mac, AES_BLOCK_SIZE_IN_BYTE, cmac.mac, AES_BLOCK_SIZE_IN_BYTE);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(memcpy_s, ret);
            return ret;
        }
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

#ifdef HI_PRODUCT_AEAD_SUPPORT
hi_s32 sys_aead_get_tag(hi_u32 id, hi_u8 *tag, hi_u32 *taglen)
{
    hi_s32 ret;
    aead_tag_t aead_tag;

    hi_dbg_func_enter();

    ret = memset_s(&aead_tag, sizeof(aead_tag), 0, sizeof(aead_tag));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    aead_tag.id = id;
    aead_tag.taglen = *taglen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SYMC_GETTAG, &aead_tag);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    ret = memcpy_s(tag, *taglen, aead_tag.tag, aead_tag.taglen);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    *taglen = aead_tag.taglen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

hi_s32 sys_hash_start(hi_u32 *id, hi_cipher_hash_type type,
                      const hi_u8 *key, hi_u32 keylen)
{
    hi_s32 ret;
    hash_start_t start;

    hi_dbg_func_enter();

    ret = memset_s(&start, sizeof(start), 0, sizeof(start));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    start.id = 0;
    start.type = type;
    start.keylen = keylen;
    ADDR_VIA(start.key) = (hi_u8 *)key;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_HASH_START, &start);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *id = start.id;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_hash_update(hi_u32 id, const hi_u8 *input, hi_u32 length, hash_chunk_src src)
{
    hi_s32 ret;
    hash_update_t update;

    hi_dbg_func_enter();

    ret = memset_s(&update, sizeof(update), 0, sizeof(update));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    update.id = id;
    ADDR_VIA(update.input) = (hi_u8 *)input;
    update.length = length;
    update.src = src;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_HASH_UPDATE, &update);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_hash_finish(hi_u32 id, hi_u8 *hash, hi_u32 *hashlen)
{
    hi_s32 ret;
    hash_finish_t finish;

    hi_dbg_func_enter();

    ret = memset_s(&finish, sizeof(finish), 0, sizeof(finish));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    finish.id = id;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_HASH_FINISH, &finish);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    ret = memcpy_s(hash, HASH_RESULT_MAX_SIZE, finish.hash, finish.hashlen);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }

    *hashlen = finish.hashlen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_RSA_SUPPORT
hi_s32 sys_rsa_encrypt(const cryp_rsa_key *key,
                       hi_cipher_rsa_enc_scheme scheme,
                       const hi_u8 *in, hi_u32 inlen,
                       hi_u8 *out, hi_u32 *outlen)
{
    hi_s32 ret;
    rsa_info_t rsa_info;

    hi_dbg_func_enter();

    ret = memset_s(&rsa_info, sizeof(rsa_info_t), 0, sizeof(rsa_info_t));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ADDR_VIA(rsa_info.n) = key->n;
    ADDR_VIA(rsa_info.d) = key->d;
    ADDR_VIA(rsa_info.p) = key->p;
    ADDR_VIA(rsa_info.q) = key->q;
    ADDR_VIA(rsa_info.dp) = key->dp;
    ADDR_VIA(rsa_info.dq) = key->dq;
    ADDR_VIA(rsa_info.qp) = key->qp;

    rsa_info.e = key->e;
    rsa_info.public = key->public;
    rsa_info.klen = key->klen;
    rsa_info.scheme = scheme;
    ADDR_VIA(rsa_info.in) = (hi_u8 *)in;
    rsa_info.inlen = inlen;
    ADDR_VIA(rsa_info.out) = out;
    rsa_info.outlen = key->klen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_RSA_ENC, &rsa_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *outlen = rsa_info.outlen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_rsa_decrypt(const cryp_rsa_key *key,
                       hi_cipher_rsa_enc_scheme scheme,
                       const hi_u8 *in, hi_u32 inlen,
                       hi_u8 *out, hi_u32 *outlen)
{
    hi_s32 ret;
    rsa_info_t rsa_info;

    hi_dbg_func_enter();

    ret = memset_s(&rsa_info, sizeof(rsa_info), 0, sizeof(rsa_info));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ADDR_VIA(rsa_info.n) = key->n;
    ADDR_VIA(rsa_info.d) = key->d;
    ADDR_VIA(rsa_info.p) = key->p;
    ADDR_VIA(rsa_info.q) = key->q;
    ADDR_VIA(rsa_info.dp) = key->dp;
    ADDR_VIA(rsa_info.dq) = key->dq;
    ADDR_VIA(rsa_info.qp) = key->qp;

    rsa_info.e = key->e;
    rsa_info.public = key->public;
    rsa_info.klen = key->klen;
    rsa_info.scheme = scheme;
    ADDR_VIA(rsa_info.in) = (hi_u8 *)in;
    rsa_info.inlen = inlen;
    ADDR_VIA(rsa_info.out) = out;
    rsa_info.outlen = key->klen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_RSA_DEC, &rsa_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *outlen = rsa_info.outlen;
    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_rsa_sign_hash(const cryp_rsa_key *key,
                         hi_cipher_rsa_sign_scheme scheme,
                         const hi_u8 *hash, hi_u32 hlen,
                         hi_u8 *sign, hi_u32 *signlen)
{
    hi_s32 ret;
    rsa_info_t rsa_info;

    hi_dbg_func_enter();

    ret = memset_s(&rsa_info, sizeof(rsa_info), 0, sizeof(rsa_info));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ADDR_VIA(rsa_info.n) = key->n;
    ADDR_VIA(rsa_info.d) = key->d;
    ADDR_VIA(rsa_info.p) = key->p;
    ADDR_VIA(rsa_info.q) = key->q;
    ADDR_VIA(rsa_info.dp) = key->dp;
    ADDR_VIA(rsa_info.dq) = key->dq;
    ADDR_VIA(rsa_info.qp) = key->qp;

    rsa_info.e = key->e;
    rsa_info.public = key->public;
    rsa_info.klen = key->klen;
    rsa_info.scheme = scheme;
    ADDR_VIA(rsa_info.in) = (hi_u8 *)hash;
    rsa_info.inlen = hlen;
    ADDR_VIA(rsa_info.out) = sign;
    rsa_info.outlen = key->klen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_RSA_SIGN, &rsa_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *signlen = rsa_info.outlen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_rsa_verify_hash(const cryp_rsa_key *key,
                           hi_cipher_rsa_sign_scheme scheme,
                           const hi_u8 *hash, hi_u32 hlen,
                           const hi_u8 *sign, hi_u32 signlen)
{
    hi_s32 ret;
    rsa_info_t rsa_info;

    hi_dbg_func_enter();

    ret = memset_s(&rsa_info, sizeof(rsa_info_t), 0, sizeof(rsa_info_t));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ADDR_VIA(rsa_info.n) = key->n;

    rsa_info.e = key->e;
    rsa_info.public = key->public;
    rsa_info.klen = key->klen;
    rsa_info.scheme = scheme;
    ADDR_VIA(rsa_info.in) = (hi_u8 *)sign;
    rsa_info.inlen = signlen;
    ADDR_VIA(rsa_info.out) = (hi_u8 *)hash;
    rsa_info.outlen = hlen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_RSA_VERIFY, &rsa_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}


#endif

hi_s32 sys_trng_get_random(hi_u8 *randnum, hi_u32 size, hi_u32 timeout)
{
    hi_s32 ret;
    trng_t trng;

    hi_dbg_func_enter();

    ret = memset_s(&trng, sizeof(trng), 0, sizeof(trng));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    ADDR_VIA(trng.randnum) = randnum;
    trng.size = size;
    trng.timeout = timeout;
    ret = CRYPTO_IOCTL(CRYPTO_CMD_TRNG, &trng);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_SM2_SUPPORT
hi_s32 sys_sm2_sign(const hi_u32 d[SM2_LEN_IN_WROD],
                    const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                    const hi_u8 *id, hi_u16 idlen,
                    const hi_u8 *msg, hi_u32 msglen, hash_chunk_src src,
                    hi_u8 r[SM2_LEN_IN_BYTE], hi_u8 s[SM2_LEN_IN_BYTE])
{
    hi_s32 ret;
    sm2_sign_t sign;

    hi_dbg_func_enter();

    ret = memset_s(&sign, sizeof(sign), 0, sizeof(sign));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ret = memcpy_s(sign.d, SM2_LEN_IN_BYTE, d, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(sign.px, SM2_LEN_IN_BYTE, px, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(sign.py, SM2_LEN_IN_BYTE, py, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ADDR_VIA(sign.id) = (hi_u8 *)id;
    sign.idlen = idlen;
    ADDR_VIA(sign.msg) = (hi_u8 *)msg;
    sign.msglen = msglen;
    sign.src = src;
    sign.magic_num = CRYPTO_MAGIC_NUM;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SM2_SIGN, &sign);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    ret = memcpy_s(r, SM2_LEN_IN_BYTE, sign.r, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(s, SM2_LEN_IN_BYTE, sign.s, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_sm2_verify(const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                      const hi_u8 *id, hi_u16 idlen, const hi_u8 *msg, hi_u32 msglen, hash_chunk_src src,
                      const hi_u8 r[SM2_LEN_IN_BYTE], const hi_u8 s[SM2_LEN_IN_BYTE])
{
    hi_s32 ret;
    sm2_verify_t verify;

    hi_dbg_func_enter();

    ret = memset_s(&verify, sizeof(verify), 0, sizeof(verify));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ret = memcpy_s(verify.px, SM2_LEN_IN_BYTE, px, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(verify.py, SM2_LEN_IN_BYTE, py, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ADDR_VIA(verify.id) = (hi_u8 *)id;
    verify.idlen = idlen;
    ADDR_VIA(verify.msg) = (hi_u8 *)msg;
    verify.msglen = msglen;
    ret = memcpy_s(verify.r, SM2_LEN_IN_BYTE, r, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(verify.s, SM2_LEN_IN_BYTE, s, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    verify.src = src;
    verify.magic_num = CRYPTO_MAGIC_NUM;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SM2_VERIFY, &verify);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_sm2_encrypt(const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                       const hi_u8 *msg, hi_u32 msglen, hi_u8 *enc, hi_u32 *enclen)
{
    hi_s32 ret;
    sm2_encrypt_t encrypt;

    hi_dbg_func_enter();

    ret = memset_s(&encrypt, sizeof(encrypt), 0, sizeof(encrypt));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ret = memcpy_s(encrypt.px, SM2_LEN_IN_BYTE, px, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(encrypt.py, SM2_LEN_IN_BYTE, py, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ADDR_VIA(encrypt.msg) = (hi_u8 *)msg;
    ADDR_VIA(encrypt.enc) = enc;
    encrypt.msglen = msglen;
    encrypt.keylen = SM2_LEN_IN_WROD;
    encrypt.magic_num = CRYPTO_MAGIC_NUM;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SM2_ENCRYPT, &encrypt);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *enclen = encrypt.enclen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_sm2_decrypt(const hi_u32 d[SM2_LEN_IN_WROD], const hi_u8 *enc,
                       hi_u32 enclen, const hi_u8 *msg, hi_u32 *msglen)
{
    hi_s32 ret;
    sm2_decrypt_t decrypt;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(enc == HI_NULL);

    ret = memset_s(&decrypt, sizeof(decrypt), 0, sizeof(decrypt));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ret = memcpy_s(decrypt.d, SM2_LEN_IN_BYTE, d, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ADDR_VIA(decrypt.enc) = (hi_u8 *)enc;
    ADDR_VIA(decrypt.msg) = (hi_u8 *)msg;
    decrypt.enclen = enclen;
    decrypt.keylen = SM2_LEN_IN_WROD;
    decrypt.magic_num = CRYPTO_MAGIC_NUM;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SM2_DECRYPT, &decrypt);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    *msglen = decrypt.msglen;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 sys_sm2_gen_key(hi_u32 d[SM2_LEN_IN_WROD], hi_u32 px[SM2_LEN_IN_WROD], hi_u32 py[SM2_LEN_IN_WROD])
{
    hi_s32 ret;
    sm2_key_t key;

    hi_dbg_func_enter();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    key.keylen = SM2_LEN_IN_WROD;
    key.magic_num = CRYPTO_MAGIC_NUM;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_SM2_GEN_KEY, &key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    ret = memcpy_s(d, SM2_LEN_IN_BYTE, key.d, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(px, SM2_LEN_IN_BYTE, key.px, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(py, SM2_LEN_IN_BYTE, key.py, SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

#ifdef HI_PRODUCT_CENC_SUPPORT
hi_s32 sys_cenc_decrypt(hi_handle handle, const hi_cipher_cenc *cenc,
                        hi_mem_handle inphy, hi_mem_handle outphy,
                        hi_u32 length)
{
    hi_s32 ret;
    cenc_info_t cenc_info;

    hi_dbg_func_enter();

    ret = memset_s(&cenc_info, sizeof(cenc_info), 0, sizeof(cenc_info));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    cenc_info.id = handle;
    cenc_info.oddkey = cenc->odd_key;
    cenc_info.inphy.mem_handle = inphy.mem_handle;
    cenc_info.inphy.addr_offset = inphy.addr_offset;
    cenc_info.outphy.mem_handle = outphy.mem_handle;
    cenc_info.outphy.addr_offset = outphy.addr_offset;
    cenc_info.length = length;
    cenc_info.firstoffset = cenc->first_offset;
    ADDR_VIA(cenc_info.subsample) = cenc->subsample;
    cenc_info.subsample_num = cenc->subsample_num;
    cenc_info.data_dir = cenc->data_dir;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_CENC, &cenc_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

/** @} */ /** <!-- ==== API Code end ==== */
