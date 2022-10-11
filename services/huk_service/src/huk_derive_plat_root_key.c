/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive plat root key
 * Create: 2022-10-08
 */
#include "huk_derive_plat_root_key.h"
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_ext_api.h>
#include <mem_ops_ext.h>
#include <tee_crypto_hal.h>
#include <crypto_driver_adaptor.h>
#include <crypto_hal_hmac.h>
#include <crypto_hal_derive_key.h>
#include <crypto_wrapper.h>
#include <oemkey.h>
#include "huk_derive_takey.h"
#include "huk_service_config.h"

/* size of HMAC output bytes */
#define SIZE_HMAC256_OBYTES 32
#define SIZE_HMAC384_OBYTES 48
#define SIZE_HMAC512_OBYTES 64

/* expand key usage, 10x for derive, 20x for crypto */
enum EXPAND_KEY_USAGE {
    EKU_FOR_DERIVE_ECC = 101,
    EKU_FOR_CRYPTO_AES = 201
};

/* KDS TA Level, bigger level means higher secure level? */
enum PLATKEY_CALLER_LEVEL {
    LEVEL_COM = 0,  /* for TAs which is not KDS TA , common TA */
    LEVEL_UND = 20, /* for KDS TA - Caller TA not defined in level */
    LEVEL_KCA = 21, /* for KDS CA2TA, caller is CA */
    LEVEL_3ST = 23, /* for KDS TA */
    LEVEL_6ST = 26, /* for KDS TA */
    LEVEL_9ST = 29, /* for KDS TA */
    LEVEL_ERR = 255
};

/* offset of the salt_ta, if sizeof(UUID) changes, we need change this */
#define SIZE_UUID       16
/* salt_ta [2-47] is reserved, now filed with 0x00 */
#define KS_OFTS_USAGE      0   /* for EXPAND_KEY_USAGE  */
#define KS_OFTS_KDS_CALLER 1   /* for PLATKEY CALLER LEVEL */
#define KS_OFTS_TA_UUID    48  /* [48 - 63]  UUID       */
#define KS_OFTS_EXINFO     64  /* [64 - 127] EXTRA INFO */
#define KS_OFTS_TOTAL      128 /* total size of salt    */

static TEE_Result huk_task_derive_plat_root_key_check_msg(const struct huk_srv_msg *msg)
{
    TEE_Result ret;

    if (msg->data.plat_key_msg.exinfo_size == 0 || msg->data.plat_key_msg.exinfo_size > SIZE_MAX_EXINFO) {
        tloge("huk msg exinfo size is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (msg->data.plat_key_msg.attri_buff == 0) {
        tloge("huk invalid msg\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (msg->data.plat_key_msg.csc_type == SESSION_FROM_UNKNOWN) {
        tloge("huk msg csc type is invalid \n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY ||
         msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY) &&
        msg->data.plat_key_msg.attri_size == SIZE_ECC256 * ATTR_BUFFER_SIZE_PUBLIC) {
        ret = TEE_SUCCESS;
    } else if ((msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDH_KEYPAIR ||
                msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDSA_KEYPAIR) &&
               msg->data.plat_key_msg.attri_size == SIZE_ECC256 * ATTR_BUFFER_SIZE_PAIR) {
        ret = TEE_SUCCESS;
    } else {
        tloge("huk input args not supported\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return ret;
}

struct salt_ta_info {
    uint8_t salt_ta[KS_OFTS_TOTAL];
    uint32_t salt_ta_size;
};
/* assemble TA platform root key derive factor */
static TEE_Result ks_get_ta_plat_root_key_salt(struct salt_ta_info *ta_salt_info, const TEE_UUID *ta_uuid,
    uint32_t caller_level, const uint8_t *exinfo, uint32_t exinfo_size)
{
    errno_t rc;
    ta_salt_info->salt_ta[KS_OFTS_USAGE] = EKU_FOR_DERIVE_ECC;
    ta_salt_info->salt_ta[KS_OFTS_KDS_CALLER] = caller_level;

    rc = memcpy_s(ta_salt_info->salt_ta + KS_OFTS_TA_UUID, ta_salt_info->salt_ta_size - KS_OFTS_TA_UUID,
                  ta_uuid, sizeof(*ta_uuid));
    if (rc != EOK) {
        tloge("memory copy ta uuid failed");
        return TEE_ERROR_SECURITY;
    }

    rc = memcpy_s(ta_salt_info->salt_ta + KS_OFTS_EXINFO, ta_salt_info->salt_ta_size - KS_OFTS_EXINFO,
                  exinfo, exinfo_size);
    if (rc != EOK) {
        tloge("memory copy ta exinfo failed");
        return TEE_ERROR_SECURITY;
    }
    return TEE_SUCCESS;
}

#define SIZE_KOEM             16
#define DATA_TEE_PRK_DRV_V100 "salt for tee platform root key derive v1.00"
static int get_tee_plat_rootkey(uint8_t *key, uint32_t keysize)
{
    uint8_t k_oem_invalid[SIZE_KOEM] = { 0 };
    uint8_t k_oem[SIZE_KOEM] = { 0 };
    uint8_t data[] = DATA_TEE_PRK_DRV_V100;

    if (tee_hal_get_provision_key(k_oem, SIZE_KOEM) != 0) {
        tloge("huk get provision key failed\n");
        return -1;
    }
    if (TEE_MemCompare(k_oem, k_oem_invalid, sizeof(k_oem)) == 0) {
        tloge("get eom key failed!");
        return -1;
    }

    struct symmerit_key_t hmac_key = {0};
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    hmac_key.key_buffer = (uintptr_t)k_oem;
    hmac_key.key_size = (uint32_t)sizeof(k_oem);
    data_in.buffer = (uintptr_t)data;
    data_in.size = (uint32_t)sizeof(data);
    data_out.buffer = (uintptr_t)key;
    data_out.size = keysize;
    int32_t hmac_rc = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA512, &hmac_key, &data_in, &data_out, SOFT_CRYPTO);
    (void)memset_s(k_oem, sizeof(k_oem), 0, sizeof(k_oem));
    if (hmac_rc != 0) {
        tloge("hmac failed");
        (void)memset_s(key, keysize, 0, keysize);
        return -1;
    }
    if (data_out.size != keysize) {
        tloge("hmac out len error, out_len=%u\n", data_out.size);
        (void)memset_s(key, keysize, 0, keysize);
        return -1;
    }
    return 0;
}

static TEE_Result ks_drv_ta_prk(uint8_t *keybuf, uint32_t keybytes, const struct huk_srv_msg *msg,
    uint32_t caller_level, const TEE_UUID *ta_uuid)
{
    TEE_Result ret;
    uint8_t tee_pltrootkey[SIZE_HMAC512_OBYTES] = {0};
    struct salt_ta_info ta_salt_info            = { { 0 }, 0 };

    ta_salt_info.salt_ta_size = KS_OFTS_TOTAL;
    ret = ks_get_ta_plat_root_key_salt(&ta_salt_info, ta_uuid, caller_level,
                                       msg->data.plat_key_msg.exinfo, msg->data.plat_key_msg.exinfo_size);
    if (ret != TEE_SUCCESS) {
        tloge(" get_TA_PRK_salt failed\n");
        return ret;
    }

    if (keybytes != SIZE_HMAC512_OBYTES) {
        tloge("keybytes no supported\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (get_tee_plat_rootkey(tee_pltrootkey, sizeof(tee_pltrootkey)) != 0) {
        tloge("huk get tee plat root key failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* derive TA platform Root Key. */
    struct symmerit_key_t hmac_key;
    struct memref_t data_in;
    struct memref_t data_out;
    hmac_key.key_buffer = (uintptr_t)tee_pltrootkey;
    hmac_key.key_size = (uint32_t)sizeof(tee_pltrootkey);
    data_in.buffer = (uintptr_t)ta_salt_info.salt_ta;
    data_in.size = ta_salt_info.salt_ta_size;
    data_out.buffer = (uintptr_t)keybuf;
    data_out.size = 0;
    int32_t result = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA512, &hmac_key, &data_in, &data_out, SOFT_CRYPTO);
    (void)memset_s(tee_pltrootkey, sizeof(tee_pltrootkey), 0, sizeof(tee_pltrootkey));
    if (result != 0) {
        tloge("hmac failed!");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t fill_ecc_key(uint8_t *key, uint32_t *key_len, uint32_t fill_size)
{
    if (*key_len == fill_size)
        return 0;
    if (*key_len > fill_size)
        return -1;
    uint32_t move_len = fill_size - *key_len;
    errno_t rc = memmove_s(key + move_len, *key_len, key, *key_len);
    if (rc != EOK) {
        tloge("ecc key fill failed");
        return -1;
    }

    rc = memset_s(key, fill_size, 0x0, move_len);
    if (rc != EOK) {
        tloge("ecc key fill failed");
        return -1;
    }
    *key_len = fill_size;
    return 0;
}

#define PRIV_KEY_OFFSET_NUM 2
static TEE_Result ks_drv_get_attr_buffer(uint32_t key_type, uint32_t keybuff_bytes,
    ecc_priv_key_t *ta_prk_priv, uint8_t *attr_buff, uint32_t attr_buff_size)
{
    errno_t ret;
    int32_t ret_c;
    ecc_pub_key_t ta_prk_pub = {0};

    switch (key_type) {
    case TEE_TYPE_ECDH_KEYPAIR:
    case TEE_TYPE_ECDSA_KEYPAIR:
        /* attr_buff's first 2/3 are for pubkey's X and Y */
        ret_c = fill_ecc_key(ta_prk_priv->r, &(ta_prk_priv->r_len), keybuff_bytes);
        if (ret_c != 0)
            return TEE_ERROR_SECURITY;
        ret = memcpy_s(attr_buff + keybuff_bytes * PRIV_KEY_OFFSET_NUM, /* the last 1/3 is for prikey's r */
                       attr_buff_size - keybuff_bytes * PRIV_KEY_OFFSET_NUM, ta_prk_priv->r, ta_prk_priv->r_len);
        if (ret != EOK) {
            tloge("copy r to buffer failed\n");
            return TEE_ERROR_SECURITY;
        }
        /* fall-through */
    case TEE_TYPE_ECDH_PUBLIC_KEY:
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
        /* derive public key by swcrypto_engine will cost 300ms */
        ret_c = ecc_derive_public_key(ta_prk_priv, &ta_prk_pub);
        if (ret_c != 0) {
            tloge("derive ecc public key failed, ret = 0x%x\n", ret_c);
            (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
            return TEE_ERROR_GENERIC;
        }
        if (fill_ecc_key(ta_prk_pub.x, &(ta_prk_pub.x_len), keybuff_bytes) != 0 ||
            fill_ecc_key(ta_prk_pub.y, &(ta_prk_pub.y_len), keybuff_bytes) != 0) {
                tloge("fill ecc public key failed\n");
                (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
                return TEE_ERROR_SECURITY;
        }
        if (memcpy_s(attr_buff, attr_buff_size, ta_prk_pub.x, ta_prk_pub.x_len) != EOK ||
            memcpy_s(attr_buff + ta_prk_pub.x_len, attr_buff_size - ta_prk_pub.x_len,
                     ta_prk_pub.y, ta_prk_pub.y_len) != EOK) {
            tloge("copy pub failed");
            (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
            return TEE_ERROR_GENERIC;
        }
        break;

    default:
        tloge("unknown key type, key type is %u\n", key_type);
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
    return TEE_SUCCESS;
}

static TEE_Result ks_drv_ecc_ta_pk(const struct huk_srv_msg *msg, uint32_t caller_level, const TEE_UUID *ta_uuid,
    uint8_t *attr_buff, uint32_t attr_size)
{
    uint8_t keybuf[SIZE_HMAC512_OBYTES] = {0};
    ecc_priv_key_t ta_prk_priv          = {0};
    TEE_Result ret;
    int ecc_ret;

    ret = ks_drv_ta_prk(keybuf, (uint32_t)sizeof(keybuf), msg, caller_level, ta_uuid);
    if (ret != TEE_SUCCESS) {
        tloge("huk ta prk failed.\n");
        (void)memset_s(keybuf, sizeof(keybuf), 0, sizeof(keybuf));
        return ret;
    }

    ecc_ret = derive_ecc_private_key_from_huk(&ta_prk_priv, keybuf, (uint32_t)sizeof(keybuf));
    /* clear ta_pltrootkey in memory */
    (void)memset_s(keybuf, sizeof(keybuf), 0, sizeof(keybuf));
    if (ecc_ret != 0) {
        tloge("huk derive ecc private key failed");
        (void)memset_s(&ta_prk_priv, sizeof(ta_prk_priv), 0, sizeof(ta_prk_priv));
        return TEE_ERROR_GENERIC;
    }

    ret = ks_drv_get_attr_buffer(msg->data.plat_key_msg.keytype, msg->data.plat_key_msg.keysize,
                                 &ta_prk_priv, attr_buff, attr_size);
    (void)memset_s(&ta_prk_priv, sizeof(ta_prk_priv), 0, sizeof(ta_prk_priv));
    return ret;
}

static uint32_t ks_get_ta_level(const uint32_t cmd_id, const TEE_UUID *caller_uuid)
{
    uint32_t level;

    /* implement level whitelist. first add HDCP_UUID */
    if (check_huk_access_permission(cmd_id, caller_uuid)) {
        level = LEVEL_3ST;
    } else {
        level = LEVEL_UND;
    }

    return level;
}

static uint32_t ks_get_caller_level(const uint32_t cmd_id, uint32_t csc_type, const TEE_UUID *csc_uuid,
    const TEE_UUID *ta_uuid)
{
    uint32_t level;

    if (check_huk_access_permission(cmd_id, ta_uuid)) {
        /* for KDS TA */
        if (csc_type == SESSION_FROM_CA) /* CA2TA for KDS TA */
            level = LEVEL_KCA;
        else
            level = ks_get_ta_level(cmd_id, csc_uuid); /* TA2TA for KDS TA */
    } else {
        /* for normal TA */
        level = LEVEL_COM;
    }
    return level;
}

#define PUBLIC_KEY_COUNT 2U
#define KEY_PAIR_COUNT   3U
static uint32_t ks_deriveta_get_count(uint32_t key_type)
{
    uint32_t attr_count;

    /*
     * attr_count here is only X, Y, PrivateExpont, with out CURVE_TYPE;
     * so (attr_count+1) is actual Attribute count for object.
     */
    switch (key_type) {
    case (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY:
        attr_count = PUBLIC_KEY_COUNT;
        break;
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
        attr_count = KEY_PAIR_COUNT;
        break;
    default:
        tloge("objectType is not supported\n");
        attr_count = 0;
    }

    return attr_count;
}

/* hdcp TA -> kds TA -> tks */
static TEE_Result ks_deriveta_platkeys(const struct huk_srv_msg *msg, const TEE_UUID *ta_uuid, uint8_t *attr_buff,
    uint32_t attr_size)
{
    TEE_Result ret = TEE_SUCCESS;
    uint32_t caller_level;
    uint32_t attr_count;
    const TEE_UUID csc_uuid = { 0, 0, 0, { 0 } };
    if (memcpy_s((void *)&csc_uuid, sizeof(csc_uuid), &(msg->data.plat_key_msg.csc_uuid),
                 sizeof(msg->data.plat_key_msg.csc_uuid)) != EOK)
        return TEE_ERROR_SECURITY;

    if (attr_buff == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    attr_count = ks_deriveta_get_count(msg->data.plat_key_msg.keytype);
    if (attr_count == 0)
        return TEE_ERROR_NOT_SUPPORTED;

    switch (msg->data.plat_key_msg.keysize) {
    case SIZE_ECC256:
        if (attr_size != (msg->data.plat_key_msg.keysize * attr_count)) {
            tloge("attribution size inconsistency\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        break;
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t cmd_id = msg->header.send.msg_id;
    /* get caller level as key derive factor */
    caller_level = ks_get_caller_level(cmd_id, msg->data.plat_key_msg.csc_type, &csc_uuid, ta_uuid);
    /* call the real worker */
    switch (msg->data.plat_key_msg.keytype) {
    case (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
        ret = ks_drv_ecc_ta_pk(msg, caller_level, ta_uuid, attr_buff, attr_size);
        break;
    default:
        tloge("object type is not supported.\n");
        ret = TEE_ERROR_NOT_SUPPORTED;
        break;
    }

    return ret;
}

TEE_Result huk_task_derive_plat_root_key(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    errno_t rc;
    uint8_t *tmpbuf = NULL;
    uint32_t tmpbuf_size;
    uint64_t vmaddr = 0;
    TEE_Result ret;

    ret = huk_task_derive_plat_root_key_check_msg(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }
    tmpbuf_size = msg->data.plat_key_msg.attri_size;
    tmpbuf = TEE_Malloc(tmpbuf_size, 0);
    if (tmpbuf == NULL) {
        tloge("huk malloc outbuf failed.\n");
        rsp->data.ret = TEE_ERROR_OUT_OF_MEMORY;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.plat_key_msg.attri_buff, tmpbuf_size, self_pid, &vmaddr) != 0) {
        tloge("huk service map plat key buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        TEE_Free(tmpbuf);
        return rsp->data.ret;
    }

    rsp->data.ret = ks_deriveta_platkeys(msg, uuid, tmpbuf, tmpbuf_size);

    if (rsp->data.ret == TEE_SUCCESS) {
        rc = memcpy_s((uint8_t *)(uintptr_t)vmaddr, tmpbuf_size, tmpbuf, tmpbuf_size);
        if (rc != EOK) {
            tloge("memory copy buffer failed. ret = %x.\n", rsp->data.ret);
            rsp->data.ret = TEE_ERROR_SECURITY;
        }
    } else {
        tloge("derive ta plat key failed.\n");
    }
    huk_srv_task_unmap(vmaddr, tmpbuf_size);
    (void)memset_s(tmpbuf, tmpbuf_size, 0, tmpbuf_size);
    TEE_Free(tmpbuf);
    return rsp->data.ret;
}
