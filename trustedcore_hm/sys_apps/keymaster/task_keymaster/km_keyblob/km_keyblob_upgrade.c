/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster upgrade keyblob process
 * Create: 2020-11-09
 */
#include "securec.h"
#include "km_tag_operation.h"
#include "keyblob.h"
#include "keymaster_defs.h"
#include "km_key_check.h"
#include "km_env.h"
#include "km_rollback_resistance.h"
#include "km_crypto_adaptor.h"
#include "km_crypto.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
static void keyblob_upgrade_match_from_sw_enforcement(const keyblob_head *keyblob)
{
    uint32_t i;
    keymaster_tag_type_t tag_type;
    keymaster_key_param_t *sw_params_to_upgrade =
        (keymaster_key_param_t *)((uint8_t *)keyblob + keyblob->sw_enforced_offset + sizeof(uint32_t));

    for (i = 0; i < *(uint32_t *)((uint8_t *)keyblob + keyblob->sw_enforced_offset); i++) {
        tag_type = keymaster_tag_get_type(sw_params_to_upgrade[i].tag);
        if (tag_type == KM_UINT) {
            if (sw_params_to_upgrade[i].tag == KM_TAG_OS_VERSION)
                sw_params_to_upgrade[i].integer = get_verify_boot_os_version();
            if (sw_params_to_upgrade[i].tag == KM_TAG_OS_PATCHLEVEL)
                sw_params_to_upgrade[i].integer = get_verify_boot_patch_level();
        }
    }
}

static void keyblob_upgrade_os_version_patch_level(const keyblob_head *keyblob)
{
    if (keyblob == NULL) {
        tloge("invalid input params keyblob to upgrade!\n");
        return; /* no need to return error code */
    }

    keymaster_key_param_t *hw_params_to_upgrade =
        (keymaster_key_param_t *)((uint8_t *)keyblob + keyblob->hw_enforced_offset + sizeof(uint32_t));
    uint32_t os_version_match = 0;
    uint32_t patch_level_match = 0;
    uint32_t i;
    keymaster_tag_type_t tag_type;

    for (i = 0; i < *(uint32_t *)((uint8_t *)keyblob + keyblob->hw_enforced_offset); i++) {
        tag_type = keymaster_tag_get_type(hw_params_to_upgrade[i].tag);
        if (tag_type == KM_UINT) {
            if (hw_params_to_upgrade[i].tag == KM_TAG_OS_VERSION) {
                hw_params_to_upgrade[i].integer = get_verify_boot_os_version();
                os_version_match = 1;
            }
            if (hw_params_to_upgrade[i].tag == KM_TAG_OS_PATCHLEVEL) {
                hw_params_to_upgrade[i].integer = get_verify_boot_patch_level();
                patch_level_match = 1;
            }
        }
    }

    bool check_match = (os_version_match == 1) && (patch_level_match == 1);
    if (check_match) {
        tlogd("The os_version and patch_level have been found in hw params");
        return;
    }

    /* not in hw-enforcement, now try sw-enforcement */
    keyblob_upgrade_match_from_sw_enforcement(keyblob);
}
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
static TEE_Result process_rollback_upgrade(const keyblob_head *keyblob_in, const keyblob_head *keyblob_out)
{
    int ret;
    bool rollback_resistance_flag = true;
    keymaster_key_param_set_t *params_enforced =
        (keymaster_key_param_set_t *)((uint8_t *)keyblob_in + keyblob_in->hw_enforced_offset);
    keymaster_purpose_t keyblob_purpose = KM_PURPOSE_ROLLBACK_RESISTANT;

    /*
     * when upgrade keyblob, hmac has been changed, then need add new hmac in RPMB, not delete old hmc in RPMB,
     * old hmc need user call km_delete_key to delete.
     */
    ret = is_key_param_suport(KM_TAG_ROLLBACK_RESISTANT, (void *)&rollback_resistance_flag, params_enforced);
    if (ret != 0) {
        /* if the KM_PURPOSE_ROLLBACK_RESISTANT is 0xBACE, this is old purpose,and don't support rollback. */
        ret = is_key_param_suport(KM_TAG_PURPOSE, (void *)&keyblob_purpose, params_enforced);
        if (ret != 0) {
            if (kb_metafile_write(keyblob_out->hmac, HMAC_SIZE) != TEE_SUCCESS) {
                tloge("keymaster rollback resistant metadata add failed\n");
                return TEE_ERROR_GENERIC;
            } else {
                tlogd("keymaster rollback resistant metadata add successfully\n");
            }
        }
    }
    return TEE_SUCCESS;
}
#endif

TEE_Result km_upgrade_version_patch_level(TEE_Param *params, keyblob_head *keyblob_in,
    uint32_t keyblob_in_size, keyblob_head *keyblob_out, uint32_t *keyblob_out_size)
{
    TEE_Result ret = check_keyblob_version(keyblob_in);
    if (ret == TEE_SUCCESS) {
        /* copy same keyblob output */
        tlogd("Don't need upgrade, copy same keyblob output\n");
        *keyblob_out_size = keyblob_in_size;
        if (params[PARAM_NBR_TWO].memref.size < *keyblob_out_size) {
            tloge("output buffer is too small, %zu/%u\n", params[PARAM_NBR_TWO].memref.size, *keyblob_out_size);
            return TEE_ERROR_BAD_PARAMETERS;
        }

        errno_t rc = memcpy_s(params[PARAM_NBR_TWO].memref.buffer, params[PARAM_NBR_TWO].memref.size,
                              keyblob_out, *keyblob_out_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        params[PARAM_NBR_TWO].memref.size = *keyblob_out_size;
        tlogd("Unnecessary to upgrade keyblob");
        return TEE_SUCCESS;
    } else if (ret != (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE) {
        tloge("invalid keyblob to upgrade\n");
        return ret;
    }

    /*
     * keymaster(version>=2) keyblob (version>=version_200) upgrade should update value of os_version and patch_level
     * check_keyblob_version has check there are KM_TAG_OS_VERSION and KM_TAG_OS_PATCHLEVEL in this keyblob.
     */
    keyblob_upgrade_os_version_patch_level(keyblob_out);
    *keyblob_out_size = keyblob_in_size;
    return KM_ERROR_KEY_REQUIRES_UPGRADE;
}

/* high version keyblob should keep its current keyblob version, while os version/patchlevel trigger upgrading */
static keymaster_uint2uint g_version_upgraded[] = {
    {VERSION_220, VERSION_520}, {VERSION_230, VERSION_530}, {VERSION_300, VERSION_500}, {VERSION_310, VERSION_510},
    {VERSION_520, VERSION_520}, {VERSION_530, VERSION_530}, {VERSION_500, VERSION_500}, {VERSION_510, VERSION_510},
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    /* VERSION_340, VERSION_540 will be upgraded to VERSION_540 when don't support inse factor. */
    {VERSION_340, VERSION_541}, {VERSION_540, VERSION_541},
    {VERSION_341, VERSION_541}, {VERSION_541, VERSION_541},
#endif
};

static TEE_Result upgrade_version(uint32_t old_version, uint32_t *new_version)
{
    if (new_version == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (look_up_table(g_version_upgraded, sizeof(g_version_upgraded) / sizeof(keymaster_uint2uint), old_version,
        new_version) != TEE_SUCCESS) {
        tloge("upgrading keyblob version %u is invalid \n", old_version);
        return TEE_ERROR_GENERIC;
    }
    tlogd("find old version %u, set new version %u\n", old_version, *new_version);
    return TEE_SUCCESS;
}

static TEE_Result km_upgrade_rpmb(keyblob_head *keyblob_in, keyblob_head *res)
{
    /* upgrade rpmb, hmac has been changed, then need add new hmac in RPMB, */
    TEE_Result ret = process_rollback_upgrade(keyblob_in, res);
    if (ret != TEE_SUCCESS)
        tloge("keymaster rollback resistant metadata add failed\n");
    return ret;
}

static TEE_Result convert_keymaterial_dx2gp(const TEE_Param *params, const keymaster_blob_t *application_id,
    keyblob_head *keyblob_in, const keyblob_head *keyblob_out, keymaster_blob_t *keyblob_gp)
{
    TEE_Result ret;
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors((keymaster_key_param_set_t *)((uint8_t *)keyblob_in +
        keyblob_in->hw_enforced_offset), (keymaster_key_param_set_t *)params[1].memref.buffer, keyblob_in->version,
        application_id, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    ret = get_new_key_material(keyblob_out, &factors, keyblob_gp);
    return ret;
}

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static TEE_Result enhanced_key_upgrade(const TEE_Param *params, const keyblob_head *keyblob_in,
    keyblob_head *keyblob_out, keymaster_blob_t *keyblob_gp, bool *re_encrypted)
{
    TEE_Result ret;
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors new_factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    int32_t has_factors = get_kb_crypto_factors((keymaster_key_param_set_t *)((uint8_t *)keyblob_out +
        keyblob_out->hw_enforced_offset), (keymaster_key_param_set_t *)params[1].memref.buffer, keyblob_out->version,
        NULL, &new_factors);
    if (has_factors == 0) {
        /* VERSION_340/540 with inse factor: re-derive new key to re-encypt keyblob. */
        tlogd("enhanced version %u upgrade to 541", keyblob_in->version);
        *re_encrypted = true;
        struct kb_crypto_factors old_factors = { new_factors.app_id, { NULL, 0 } };
        ret = re_encrypt_keyblob(&old_factors, &new_factors, keyblob_in, keyblob_out, keyblob_gp);
        if (ret != TEE_SUCCESS) {
            tloge("re encrypt keyblob failed, %x", ret);
            return ret;
        }
    } else {
        /* VERSION_340/VERSION_540 will be upgraded to VERSION_540 when don't support inse factor. */
        tlogd("enhanced version %u upgrade to 540", keyblob_in->version);
        *re_encrypted = false;
        keyblob_out->version = VERSION_540;
    }
    return TEE_SUCCESS;
}
#endif

static TEE_Result km_upgrade_finish(TEE_Param *params, keyblob_head *keyblob_in, keymaster_blob_t *keyblob_gp,
    const keymaster_blob_t *application_id)
{
    TEE_Result ret;
    params[PARAM_NBR_TWO].memref.size = keyblob_gp->data_length;
    keyblob_head *res = (keyblob_head *)keyblob_gp->data_addr;
    /* re-calculate HMAC */
    ret = keymaster_hmac(keyblob_gp->data_addr + HMAC_SIZE, keyblob_gp->data_length - HMAC_SIZE, res->hmac,
        GENERATE_HMAC, NULL, res->version, application_id);
    if (ret != 0) {
        tloge("upgrade finish: keyblob_HMAC failed");
        return TEE_ERROR_GENERIC;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    ret = km_upgrade_rpmb(keyblob_in, res);
#endif
    return ret;
}

TEE_Result km_upgrade_end(TEE_Param *params, keyblob_head *keyblob_in, keyblob_head *keyblob_out,
    keymaster_blob_t *application_id)
{
    if (params == NULL || keyblob_in == NULL || keyblob_out == NULL || application_id == NULL) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = upgrade_version(keyblob_in->version, &(keyblob_out->version));
    if (ret != TEE_SUCCESS) {
        tloge("upgrade version failed, %x", ret);
        return TEE_ERROR_GENERIC;
    }
    keymaster_blob_t keyblob_gp = { params[PARAM_NBR_TWO].memref.buffer, params[PARAM_NBR_TWO].memref.size };

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if ((keyblob_in->version == VERSION_340 || keyblob_in->version == VERSION_540)) {
        bool re_encrypted = true;
        ret = enhanced_key_upgrade(params, keyblob_in, keyblob_out, &keyblob_gp, &re_encrypted);
        if (ret != TEE_SUCCESS) {
            tloge("enhanced key upgrade failed, %x", ret);
            return TEE_ERROR_GENERIC;
        }
        /* VERSION_340/VERSION_540 with inse factor upgrade to VERSION_541 */
        if (re_encrypted)
            goto upgrade_finish;
        /* VERSION_340/VERSION_540 without inse factor upgrade to VERSION_540 */
    }
#endif
    if (keyblob_in->version < VERSION_500) {
        tlogd("convert keymaterial to new format");
        ret = convert_keymaterial_dx2gp(params, application_id, keyblob_in, keyblob_out, &keyblob_gp);
        if (ret != TEE_SUCCESS) {
            tloge("get_new_key_material ret = %x", ret);
            return ret;
        }
    } else {
        tlogd("copy keyblob to gp keyblob");
        if (memcpy_s(keyblob_gp.data_addr, keyblob_gp.data_length, (uint8_t *)keyblob_out,
            keyblob_out->keyblob_total_size) != EOK) {
            tloge("build new key blob out fail");
            return TEE_ERROR_GENERIC;
        }
        keyblob_gp.data_length = keyblob_out->keyblob_total_size;
    }
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
upgrade_finish:
#endif
    return km_upgrade_finish(params, keyblob_in, &keyblob_gp, application_id);
}