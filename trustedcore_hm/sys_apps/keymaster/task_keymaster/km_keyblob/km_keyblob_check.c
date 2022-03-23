/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster keyblob check
 * Create: 2020-11-09
 */

#include "km_tag_operation.h"
#include "keyblob.h"
#include "km_types.h"
#include "km_key_check.h"
#include "km_env.h"
#include "km_rollback_resistance.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
TEE_Result check_compare_hmac(const uint8_t *p, uint32_t keyblob_size, const keyblob_head *key_blob,
                              const keymaster_blob_t *application_id, int valid_key_blob_ret)
{
    uint8_t hmac_result[HMAC_SIZE] = { 0 };
    int adaptable;
    bool check = (p == NULL || key_blob == NULL || application_id == NULL);
    if (check) {
        tloge("check compare hmac input error");
        return TEE_ERROR_GENERIC;
    }
    /*
     * calculate hmac
     * After LOCK_ORANGE was made to generate the same key with LOCK_GREEN,
     * to adapt old version, we'll check again with an adaptable color
     * after first check failed.
     */
    if (keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_result, CHECK_ORIGINAL_LOCK_COLOR, &adaptable,
                       key_blob->version, application_id) != 0) {
        tloge("keyblob_HMAC failed\n");
        return (TEE_Result)valid_key_blob_ret;
    }

    if (TEE_MemCompare(hmac_result, key_blob->hmac, HMAC_SIZE) != 0) {
        if (adaptable == NEED_CHECK_ADAPTABLE_COLOR) {
            if (keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_result, CHECK_ADAPTABLE_LOCK_COLOR, NULL,
                               key_blob->version, application_id) != 0) {
                tloge("keyblob_HMAC 2 failed\n");
                return TEE_ERROR_GENERIC;
            }
            if (TEE_MemCompare(hmac_result, key_blob->hmac, HMAC_SIZE) != 0) {
                tloge("hmac compare2 failed\n");
                return valid_key_blob_ret;
            }
        } else {
            tloge("hmac compare failed\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result verify_keyblob_before_delete(const keyblob_head *key_blob, uint32_t keyblob_buff_len,
    const uint8_t *keyblob_buffer)
{
    TEE_Result tee_ret;
    /*
     * static function for decrease the NSIQ, the caller (km_delete_key function)
     * must make sure the keyblob_buffer contains all of the key_blob data.
     */
    if ((key_blob == NULL) || (keyblob_buffer == NULL)) {
        tloge("Input parameter is a NULL pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_blob_internal_check(key_blob, keyblob_buff_len) != TEE_SUCCESS) {
        tloge("key_blob_internal_check failed\n");     /* check key_blob */
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }
    /*
     * The application_id is not used during the verification with most key_blob versions excluding
     *  Version300/VERSION500 and version310/VERSION_510.
     * IF Version300/500 or VERSION_310/510 try to verify the HMAC, its hmac verification need application.data,
     * but this function can't get that.
     * So,If key_blob version 300/500 or VERSION_310/510 do HMAC verification, it just passes.
     */
    bool abnormal_version = ((key_blob->version == VERSION_300) || (key_blob->version == VERSION_310) ||
        (key_blob->version == VERSION_500) || (key_blob->version == VERSION_510));
    if (abnormal_version) {
        tloge("Verification unsupported, This version %u key_blob need a KM_TAG_APPLICATION_ID\n", key_blob->version);
        return (TEE_Result)KM_ERROR_OK;
    }

    keymaster_blob_t application_id = { NULL, 0 };
    const uint8_t *kb_p = (uint8_t *)keyblob_buffer;
    /* compare hmac */
    tee_ret = check_compare_hmac(kb_p, keyblob_buff_len, key_blob, &application_id, TEE_ERROR_GENERIC);
    if (tee_ret != TEE_SUCCESS) {
        tloge("HMAC compare failed, tee_ret is 0x%x\n", tee_ret);
        return tee_ret;
    }

    tlogd("Verify key_blob HMAC OK\n");
    return (TEE_Result)KM_ERROR_OK;
}

TEE_Result key_blob_internal_check(const keyblob_head *key_blob, uint32_t buff_len)
{
    /*
     * Normally, key_blob is always secure while hmac-check passed,
     * the internal offset and block size generated in keymaster TA
     */
    if (key_blob == NULL) {
        tloge("key_blob null pointer\n");
        return (TEE_Result)KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (key_blob->keyblob_total_size != buff_len) {
        tloge("key_blob total size %u is not equal the buffer len %u\n", key_blob->keyblob_total_size, buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_blob->magic != KM_MAGIC_NUM) {
        tloge("check key blob magic failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool invalid_keyblob = (key_blob->keymaterial_offset != sizeof(keyblob_head) ||
        key_blob->keymaterial_offset > key_blob->keyblob_total_size ||
        key_blob->keyblob_total_size - key_blob->keymaterial_offset < key_blob->keymaterial_size ||
        key_blob->hw_enforced_offset != key_blob->keymaterial_size + key_blob->keymaterial_offset ||
        key_blob->hw_enforced_offset > key_blob->sw_enforced_offset ||
        key_blob->sw_enforced_offset > key_blob->extend1_buf_offset ||
        key_blob->extend1_buf_offset > key_blob->hidden_offset ||
        key_blob->hidden_offset - key_blob->extend1_buf_offset != key_blob->extend1_size ||
        key_blob->hidden_offset > key_blob->extend2_buf_offset ||
        key_blob->extend2_buf_offset > key_blob->keyblob_total_size ||
        key_blob->keyblob_total_size - key_blob->extend2_buf_offset != key_blob->extend2_size);
    if (invalid_keyblob) {
        tloge("invalid keyblob interal offset and buff size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result rsa_keymaterial_internal_check(const uint8_t *keymaterial, uint32_t len)
{
    if (keymaterial == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (len < sizeof(struct keymaterial_rsa_header)) {
        tloge("invalid keymaterial size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    const struct keymaterial_rsa_header *p = (struct keymaterial_rsa_header *)keymaterial;
    if (p->magic != KM_MAGIC_NUM) {
        tloge("magic is 0x%x, keymaterial is invalid\n", p->magic);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((len - sizeof(struct keymaterial_rsa_header)) < p->key_buff_len) {
        tloge("keymaterial size is %u, key buff len is %u, keymaterial is invalid\n", len,
            p->key_buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result calculate_hmac_2(const uint8_t *p, uint32_t keyblob_size, uint8_t *hmac_reslut, int adaptable,
                                   const keyblob_head *keyblob, const keymaster_blob_t *application_id)
{
    if (adaptable == 1) {
        int ret = keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_reslut, KM_NUM_TWO, NULL,
                                 keyblob->version, application_id);
        if (ret != 0) {
            tloge("keyblob_HMAC 2 failed\n");
            return TEE_ERROR_GENERIC;
        }
        ret = (int)TEE_MemCompare(hmac_reslut, keyblob->hmac, HMAC_SIZE);
        if (ret != 0) {
            tloge("HMAC compare2 failed\n");
            return TEE_ERROR_GENERIC;
        }
    } else {
        tloge("HMAC compare failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result calculate_hmac(uint8_t *p, uint32_t keyblob_size, uint8_t *hmac_reslut, int *adaptable,
    const keyblob_head *keyblob, const keymaster_blob_t *application_id)
{
    TEE_Result ret;
    int iret;

    iret = keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_reslut, 1, adaptable, keyblob->version,
                          application_id);
    if (iret != 0) {
        tloge("keyblob_HMAC failed\n");
        return TEE_ERROR_GENERIC;
    }

    iret = TEE_MemCompare(hmac_reslut, keyblob->hmac, HMAC_SIZE);
    if (iret != 0) {
        ret = calculate_hmac_2(p, keyblob_size, hmac_reslut, *adaptable, keyblob, application_id);
        if (ret != TEE_SUCCESS)
            return ret;
    }
    return TEE_SUCCESS;
}
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
/*
 * The caller should valid the keyblob.
 * If KM_PURPOSE_ROLLBACK_RESISTANT supports, then check whether KM_TAG_ROLLBACK_RESISTANT is true.
 */
TEE_Result check_keyblob_rollback(const keyblob_head *keyblob)
{
    if (keyblob == NULL) {
        tloge("keyblob is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t ret;
    bool kb_rollback_resistant = true;
    uint8_t *tmp = (uint8_t *)keyblob;
    keymaster_purpose_t keyblob_purpose = KM_PURPOSE_ROLLBACK_RESISTANT;
    keymaster_key_param_set_t *params_enforced = (keymaster_key_param_set_t *)(tmp + keyblob->hw_enforced_offset);
    if (is_key_param_suport(KM_TAG_ROLLBACK_RESISTANT, (void *)&kb_rollback_resistant, params_enforced)) {
        if (is_key_param_suport(KM_TAG_PURPOSE, (void *)&keyblob_purpose, params_enforced)) {
            ret = kb_metafile_find(keyblob->hmac, HMAC_SIZE);
            if (ret != 0) {
                tloge("keyblob HMAC not found or been disabled ret=0x%x\n", ret);
                return (TEE_Result)KM_ERROR_VERIFICATION_FAILED;
            } else {
                tlogd("keyblob rollback-resistant tag found and verified successfully\n");
                return TEE_SUCCESS;
            }
        } else {
            tloge("not valid rollback purpose");
        }
    }
    tlogd("keyblob rollback-resistant tag not found\n");
    return TEE_SUCCESS;
}
#endif

TEE_Result verify_keyblob(const keyblob_head *key_blob, uint32_t keyblob_size, const keymaster_blob_t *application_id)
{
    uint8_t *p = (uint8_t *)key_blob;
    if (key_blob_internal_check(key_blob, keyblob_size) != TEE_SUCCESS) {
        tloge("key_blob_internal_check failed\n");     /* check key_blob */
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }

    /* compare hmac */
    TEE_Result ret = check_compare_hmac(p, keyblob_size, key_blob, application_id, KM_ERROR_INVALID_KEY_BLOB);
    if (ret != TEE_SUCCESS) {
        tloge("HMAC compare failed:0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result keyblob_check(const keyblob_head *key_blob, uint32_t keyblob_size, const keymaster_blob_t *application_id)
{
    TEE_Result ret = verify_keyblob(key_blob, keyblob_size, application_id);
    if (ret != TEE_SUCCESS) {
        tloge("verify keyblob failed:0x%x\n", ret);
        return ret;
    }

    /* check keyblob version and KM_TAG_OS_VERSION and KM_TAG_OS_PATCHLEVEL */
    ret = check_keyblob_version(key_blob);
    if (ret != TEE_SUCCESS && ret != (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE) {
        tloge("key blob version check faild\n");
        return ret;
    }
    if (ret == (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE) {
        tloge("key blob need upgrade\n");
        return ret;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    ret = check_keyblob_rollback(key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("check_keyblob_rollback() failed\n");
        return ret;
    }
#endif
    return TEE_SUCCESS;
}

static void get_os_version_and_patch_level_from_enforce(const keymaster_key_param_set_t *enforced, uint32_t *os_version,
    uint32_t *patch_level, char *os_version_match, char *patch_level_match)
{
    uint32_t i;
    keymaster_tag_type_t tag_type;
    keymaster_key_param_t *params = (keymaster_key_param_t *)((char *)enforced + sizeof(enforced->length));
    for (i = 0; i < enforced->length; i++) {
        tag_type = keymaster_tag_get_type(params[i].tag);
        if (tag_type == KM_UINT) {
            if (params[i].tag == KM_TAG_OS_VERSION) {
                *os_version = params[i].integer;
                *os_version_match = 1;
            }
            if (params[i].tag == KM_TAG_OS_PATCHLEVEL) {
                *patch_level = params[i].integer;
                *patch_level_match = 1;
            }
        }
        if (*os_version_match != 0 && *patch_level_match != 0)
            break;
    }
}

static int get_os_version_and_patch_level_from_keyblob(const keyblob_head *keyblob, uint32_t *os_version,
                                                       uint32_t *patch_level)
{
    bool check_fail = (keyblob == NULL) || (os_version == NULL) || (patch_level == NULL);
    if (check_fail) {
        tloge("invalid input params keyblob, osversion or patchlevel!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keymaster_key_param_set_t *hw_enforced =
        (keymaster_key_param_set_t *)((char *)keyblob + keyblob->hw_enforced_offset);
    char os_version_match = 0;
    char patch_level_match = 0;

    get_os_version_and_patch_level_from_enforce(hw_enforced, os_version,
        patch_level, &os_version_match, &patch_level_match);
    bool check_match = (os_version_match == 1) && (patch_level_match == 1);
    if (check_match)
        return 0;

    /* no os_version and patch_level found in hw-enforcement
     * now try get from sw-enforcement */
    os_version_match = 0;
    patch_level_match = 0;
    keymaster_key_param_set_t *sw_enforced =
        (keymaster_key_param_set_t *)((char *)keyblob + keyblob->sw_enforced_offset);

    get_os_version_and_patch_level_from_enforce(sw_enforced, os_version,
        patch_level, &os_version_match, &patch_level_match);
    check_match = (os_version_match == 0) || (patch_level_match == 0);
    if (check_match) {
        tloge("the paramter of os_version_match or patch_level_match is 0\n");
        return -1;
    }

    return 0;
}

static TEE_Result check_keyblob_high_version_by_patch_level(uint32_t patch_level0, uint32_t patch_level1,
    uint32_t os_version0, uint32_t os_version1)
{
    /*
     * Note that keys with an OS version number that does not match the current OS version may be used and
     * must not be rejected if the patch level matches.
     */
    if (patch_level1 == patch_level0) {
        tlogd("check keyblob version success: patch_level match\n");
        return TEE_SUCCESS;
    }
    /* Would have been a downgrade. Not allowed. */
    if (patch_level1 > patch_level0) {
        tloge("Rollback Use: keyblob version not matched, keyblob version-%u-%u, boot version-%u-%u\n", os_version1,
            patch_level1, os_version0, patch_level0);
        return (TEE_Result)KM_ERROR_INVALID_ARGUMENT;
    }

    if (patch_level1 < patch_level0) {
        tloge("Keyblob patch_level low,need upgrade: keyblob version-%u-%u, boot version-%u-%u\n",
            os_version1, patch_level1, os_version0, patch_level0);
        return (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE;
    }

    return TEE_SUCCESS;
}

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static bool check_keyblob_high_version_by_inse_factor(const keyblob_head *keyblob)
{
    /* keyblob version_540 need upgrade when support inse factor */
    if (keyblob->version == VERSION_540) {
        uint8_t temp[MAX_INSE_FACTOR_LEN] = { 0 };
        keymaster_blob_t inse_factor = { temp, sizeof(temp) };
        if (get_inse_factor((keymaster_key_param_set_t *)((uint8_t *)keyblob + keyblob->hw_enforced_offset),
            &inse_factor) == TEE_SUCCESS) {
            tlogd("find inse factor, need upgrade");
            return true;
        }
    }
    return false;
}
#endif

static TEE_Result check_keyblob_version_high_version(const keyblob_head *keyblob)
{
    uint32_t os_version0 = get_verify_boot_os_version();
    uint32_t patch_level0 = get_verify_boot_patch_level();
    uint32_t os_version1 = 0;
    uint32_t patch_level1 = 0;
    if (get_os_version_and_patch_level_from_keyblob(keyblob, &os_version1, &patch_level1) !=  0) {
        tloge("os_version and patch_level must contained in keyblob\n");
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }
    if (os_version1 > os_version0 && os_version0 != 0) {
        tloge("keyblob os_version %u is greater than system one %u\n", os_version1, os_version0);
        return (TEE_Result)KM_ERROR_INVALID_ARGUMENT;
    }
    bool check_os_version = (os_version1 < os_version0) || ((os_version0 == 0) && (os_version1 != 0));
    if (check_os_version) {
        tloge("Keyblob os_version low,need upgrade: keyblob version-%u-%u, boot version-%u-%u\n",
            os_version1, patch_level1, os_version0, patch_level0);
        return (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE;
    }

    TEE_Result ret = check_keyblob_high_version_by_patch_level(patch_level0, patch_level1, os_version0, os_version1);
    if (ret != TEE_SUCCESS)
        return ret;

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (check_keyblob_high_version_by_inse_factor(keyblob))
        return (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE;
#endif
    return TEE_SUCCESS;
}
TEE_Result check_keyblob_version(const keyblob_head *keyblob)
{
    if (keyblob == NULL) {
        tloge("invalid input params keyblob!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool deprecated_version = ((keyblob->version == VERSION_100) || (keyblob->version == VERSION_110) ||
        (keyblob->version == VERSION_200) || (keyblob->version == VERSION_210));
    bool is_low_version = ((keyblob->version == VERSION_220) || (keyblob->version == VERSION_230) ||
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        (keyblob->version == VERSION_300) || (keyblob->version == VERSION_310) || (keyblob->version == VERSION_340) ||
        (keyblob->version == VERSION_341));
#else
        (keyblob->version == VERSION_300) || (keyblob->version == VERSION_310));
#endif
    bool is_high_version = (keyblob->version == VERSION_500 || keyblob->version == VERSION_510 ||
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        keyblob->version == VERSION_520 || keyblob->version == VERSION_530 || keyblob->version == VERSION_540 ||
        keyblob->version == VERSION_541);
#else
        keyblob->version == VERSION_520 || keyblob->version == VERSION_530);
#endif
    if (is_low_version) {
        tlogd("Keyblob is low version %u, need to upgrade\n", keyblob->version);
        return (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE;
    } else if (is_high_version) {
        return check_keyblob_version_high_version(keyblob);
    } else {
        if (deprecated_version)
            tloge("the keyblob version is too old, it's deprecated, %u\n", keyblob->version);
        else
            tloge("invalid version in keyblob, %u\n", keyblob->version);
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }
}

static TEE_Result upgrading_keyblob_check_hmac(const keyblob_head *keyblob, uint32_t keyblob_size,
    const keymaster_blob_t *application_id)
{
    uint8_t hmac_reslut[HMAC_SIZE] = { 0 };
    int adaptable;
    /*
     * calculate HMAC
     * After LOCK_ORANGE was made to generate the same key with LOCK_GREEN,
     * to adapt old version, we'll check again with an adaptable color
     * after first check failed.
     */
    int ret = keymaster_hmac((uint8_t *)keyblob + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_reslut, 1, &adaptable,
                             keyblob->version, application_id);
    if (ret != 0) {
        tloge("keyblob_HMAC failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (TEE_MemCompare(hmac_reslut, keyblob->hmac, HMAC_SIZE)) {
        if (adaptable == 1) {
            if (keymaster_hmac((uint8_t *)keyblob + HMAC_SIZE, keyblob_size - HMAC_SIZE, hmac_reslut,
                PARAM_SIZE_TWO, NULL, keyblob->version, application_id) != 0) {
                tloge("keyblob_HMAC 2 failed\n");
                return TEE_ERROR_GENERIC;
            }
            if (TEE_MemCompare(hmac_reslut, keyblob->hmac, HMAC_SIZE) != 0) {
                tloge("HMAC compare2 failed\n");
                return TEE_ERROR_GENERIC;
            }
        } else {
            tloge("HMAC compare failed\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result upgrading_keyblob_check(keyblob_head *keyblob, uint32_t keyblob_size, keymaster_blob_t *application_id)
{
    if (key_blob_internal_check(keyblob, keyblob_size) != TEE_SUCCESS) {
        tloge("key_blob_internal_check failed\n");     /* check key_blob */
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }

    TEE_Result ret = upgrading_keyblob_check_hmac(keyblob, keyblob_size, application_id);
    if (ret != TEE_SUCCESS)
        return ret;

    bool con = ((keyblob->extend2_buf_offset > keyblob->hidden_offset) &&
         ((UINT32_MAX - keyblob->extend2_size) < (keyblob->extend2_buf_offset - keyblob->hidden_offset)));
    if (con) {
        tloge("check hidden size failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    /* verify APPLICATION_ID and APPLICATION_DATA ,error return KM_ERROR_INVALID_KEY_BLOB;
     * required by google in v1 */
    ret = check_keyblob_rollback(keyblob);
    if (ret != TEE_SUCCESS) {
        tloge("check_keyblob_rollback() failed\n");
        return ret;
    }
#endif
    return TEE_SUCCESS;
}