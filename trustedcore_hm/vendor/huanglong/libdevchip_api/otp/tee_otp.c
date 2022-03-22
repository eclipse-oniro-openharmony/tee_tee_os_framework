/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:The file defines the interfaces of otp drive.
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */

#include "tee_otp.h"
#include "hi_tee_otp.h"
#include "tee_otp_define.h"
#include "otp_data.h"
#include "tee_otp_func.h"
#include "tee_otp_syscall.h"

#define OTP_TA_VERION_BUF_LEN    0x07
#define OTP_TA_VERSION_LEN       0x06
#define OTP_TA_CERT_VERSION_LEN  0x02
#define RUNTIME_CHECK_EN         0x1

hi_void otp_hex_dump(const hi_u8 *buf, hi_u32 len)
{
    const hi_u32 lwidth = 0x200;
    hi_char str_buf[0x200];
    hi_char *p = str_buf;
    hi_char *q = str_buf + lwidth;
    hi_u32 i;

    p = str_buf;
    if (buf == NULL) {
        snprintf_s(p, q - p, q - p - 1, "*NULL*\n");
    } else if (len < (lwidth / 0x2)) {
        for (i = 0; i < len; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        *p = '\n';
        p++;
        *p = 0; /* end string with null char */
    } else {
        for (i = 0; i < (lwidth / 0x4) - 1; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        snprintf_s(p, q - p, q - p - 1, " ... ");
        p += 0x5;
        for (i = len - (lwidth / 0x4) + 1; i < len; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        *p = '\n';
        p++;
        *p = 0; /* end string with null char */
    }
    hi_err_otp("%s", str_buf);
    return;
}

hi_s32 otp_pv_item_unlock_write(const hi_char *field_name, const hi_u8 *value, hi_u32 value_len)
{
    hi_s32 ret;

    ret = otp_func_burn_item(field_name, value, value_len, HI_FALSE);
    if (ret != HI_SUCCESS) {
        print_err_string((const hi_u8*)value, value_len);
        print_err_hex2(ret, value_len);
    }
    return ret;
}

hi_s32 otp_pv_item_write(const hi_char *field_name, const hi_u8 *value, hi_u32 value_len)
{
    hi_s32 ret;

    if (field_name == HI_NULL || value == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = otp_func_burn_item(field_name, value, value_len, HI_TRUE);
    if (ret != HI_SUCCESS) {
        print_err_string((const hi_u8*)value, value_len);
        print_err_hex2(ret, value_len);
    }

out:
    return ret;
}

hi_s32 otp_pv_item_read(const hi_char *field_name, hi_u8 *value, hi_u32 *value_len)
{
    hi_s32 ret;

    if (field_name == HI_NULL || value == HI_NULL || value_len == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = otp_func_read_item(field_name, value, value_len);
    if (ret != HI_SUCCESS) {
        print_err_hex(ret);
    }

out:
    return ret;
}

hi_s32 otp_pv_item_write_off(const hi_char *field_name, hi_u32 offset, const hi_u8 *value, hi_u32 value_len)
{
    hi_s32 ret;

    ret = otp_func_burn_item_off(field_name, offset, value, value_len, HI_TRUE);
    if (ret != HI_SUCCESS) {
        print_err_string((const hi_u8*)value, value_len);
        print_err_hex3(ret, offset, value_len);
    }
    return ret;
}

hi_s32 otp_pv_item_read_off(const hi_char *field_name, hi_u32 offset, hi_u8 *value, hi_u32 *value_len)
{
    hi_s32 ret;

    ret = otp_func_read_item_off(field_name, offset, value, value_len);
    if (ret != HI_SUCCESS) {
        print_err_hex2(offset, ret);
    }
    return ret;
}

hi_s32 otp_pv_item_write_lock(const hi_char *field_name)
{
    hi_s32 ret;

    ret = otp_func_write_item_lock(field_name);
    if (ret != HI_SUCCESS) {
        print_err_hex(ret);
    }
    return ret;
}

hi_s32 otp_pv_item_read_lock(const hi_char *field_name, hi_bool *lock)
{
    hi_s32 ret;

    ret = otp_func_read_item_lock(field_name, lock);
    if (ret != HI_SUCCESS) {
        print_err_hex(ret);
    }
    return ret;
}

hi_s32 hi_tee_otp_init(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_otp_deinit(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_otp_reset(hi_void)
{
    return otp_syscall_reset();
}

static hi_s32 __otp_get_chip_id_field(hi_tee_otp_chipid_sel chip_id_sel, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (chip_id_sel) {
        case HI_TEE_OTP_CHIPID0:
            *field_id = field->chip_id_0;
            return HI_SUCCESS;
        case HI_TEE_OTP_CHIPID1:
            *field_id = field->chip_id_1;
            return HI_SUCCESS;
        case HI_TEE_OTP_CHIPID2:
            *field_id = field->chip_id_2;
            return HI_SUCCESS;
        default:
            break;
    }

    return HI_ERR_OTP_INVALID_PARA;
}

hi_s32 hi_tee_otp_get_ca_chip_id(hi_tee_otp_chipid_sel chip_id_sel, hi_u8 *chip_id, hi_u32 *len)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;

    if (chip_id == HI_NULL || len == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }

    if (chip_id_sel >= HI_TEE_OTP_CHIPID_MAX || *len < 0x8) {
        print_err_hex2(chip_id_sel, *len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_chip_id_field(chip_id_sel, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_chip_id_field, ret);
        return ret;
    }

    return otp_pv_item_read((const hi_char *)field_id, chip_id, len);
}

hi_s32 hi_tee_otp_get_chip_id(hi_u8 *chip_id, hi_u32 *len)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    return otp_pv_item_read((const hi_char *)field->dieid0, chip_id, len);
}

hi_s32 hi_tee_otp_read_word(hi_u32 addr, hi_u32 *value)
{
    return otp_syscall_read(addr, value);
}

hi_s32 hi_tee_otp_read_byte(hi_u32 addr, hi_u8 *value)
{
    return otp_syscall_read_byte(addr, value);
}

hi_s32 hi_tee_otp_write(hi_u32 addr, hi_u32 value)
{
    return otp_syscall_write(addr, value);
}

hi_s32 hi_tee_otp_write_byte(hi_u32 addr, hi_u8 value)
{
    return otp_syscall_write_byte(addr, value);
}

static hi_s32 __otp_get_rk_slot_field(hi_tee_otp_rootkey root_key_slot, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (root_key_slot) {
        case HI_TEE_OTP_BOOT_ROOTKEY0:
            *field_id = field->boot_rootkey;
            return HI_SUCCESS;
        case HI_TEE_OTP_OEM_ROOTKEY0:
            *field_id = field->stbm_rootkey;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY0:
            *field_id = field->cas_rootkey_0;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY1:
            *field_id = field->cas_rootkey_1;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY2:
            *field_id = field->cas_rootkey_2;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY3:
            *field_id = field->cas_rootkey_3;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY4:
            *field_id = field->cas_rootkey_4;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY5:
            *field_id = field->cas_rootkey_5;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY6:
            *field_id = field->cas_rootkey_6;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY7:
            *field_id = field->cas_rootkey_7;
            return HI_SUCCESS;
        default:
            break;
    }
    return HI_ERR_OTP_INVALID_PARA;
}

hi_s32 hi_tee_otp_set_root_key(hi_tee_otp_rootkey root_key_slot, const hi_u8 *root_key, hi_u32 len)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;

    if (root_key == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != OTP_KEY_LENGTH || root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX) {
        print_err_hex2(root_key_slot, len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_rk_slot_field(root_key_slot, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_rk_slot_field, ret);
        return ret;
    }

    return otp_pv_item_write((const hi_char *)field_id, root_key, len);
}

hi_s32 hi_tee_otp_get_root_key_lock_stat(hi_tee_otp_rootkey root_key_slot, hi_bool *lock)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;

    if (lock == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX) {
        print_err_hex2((root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX), root_key_slot);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_rk_slot_field(root_key_slot, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_rk_slot_field, ret);
        return ret;
    }

    return otp_pv_item_read_lock(field_id, lock);
}


static hi_s32 __otp_get_rk_slot_flag_field(hi_tee_otp_rootkey root_key_slot, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (root_key_slot) {
        case HI_TEE_OTP_BOOT_ROOTKEY0:
            *field_id = field->boot_slot_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_OEM_ROOTKEY0:
            *field_id = field->stbm_slot_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY0:
            *field_id = field->cas_slot0_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY1:
            *field_id = field->cas_slot1_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY2:
            *field_id = field->cas_slot2_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY3:
            *field_id = field->cas_slot3_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY4:
            *field_id = field->cas_slot4_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY5:
            *field_id = field->cas_slot5_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY6:
            *field_id = field->cas_slot6_flag;
            return HI_SUCCESS;
        case HI_TEE_OTP_CAS_ROOTKEY7:
            *field_id = field->cas_slot7_flag;
            return HI_SUCCESS;
        default:
            break;
    }
    return HI_ERR_OTP_INVALID_PARA;
}

hi_s32 hi_tee_otp_set_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot,
                                         const hi_tee_otp_rootkey_slot_flag *pst_slot_flag)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;
    struct pv_item pv = {0};

    if (pst_slot_flag == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX) {
        print_err_hex2((root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX), root_key_slot);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_rk_slot_flag_field(root_key_slot, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_rk_slot_flag_field, ret);
        return ret;
    }

    pv.value_len = 0x04;
    u32tou8(pst_slot_flag->slot_flag, pv.value);

    return otp_pv_item_write((const hi_char *)field_id, pv.value, pv.value_len);
}

hi_s32 hi_tee_otp_get_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot, hi_tee_otp_rootkey_slot_flag *pst_slot_flag)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;
    struct pv_item pv = {0};

    if (pst_slot_flag == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX) {
        print_err_hex2((root_key_slot >= HI_TEE_OTP_ROOTKEY_MAX), root_key_slot);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_rk_slot_flag_field(root_key_slot, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_rk_slot_flag_field, ret);
        return ret;
    }

    pv.value_len = 0x04;
    ret = otp_pv_item_read((const hi_char *)field_id, pv.value, &pv.value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_chip_id_field, ret);
        return ret;
    }
    u8tou32(pv.value, pst_slot_flag->slot_flag);
    return HI_SUCCESS;
}

static hi_u32 __otp_bit_count(hi_u8 value)
{
    hi_u32 count = 0;

    while (value > 0) {
        if ((value & 1) == 1) {
            ++count;
        }

        value >>= 1;
    }

    return count;
}

static hi_s32 __otp_count_version_num(const hi_char *field_name, hi_u32 length, hi_u32 *version)
{
    hi_s32 ret;
    hi_u32 i;
    hi_u32 count = 0;
    hi_u8 value[OTP_TA_VERSION_LEN] = {0};

    ret = otp_pv_item_read(field_name, value, &length);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_pv_item_read, ret);
        goto out;
    }

    for (i = 0; i < length; i++) {
        count += __otp_bit_count(value[i]);
    }

    *version = count;

out:
    return ret;
}

static hi_s32 __otp_set_version_num(const hi_char *field_name, hi_u32 length)
{
    hi_u32 i = 0;
    hi_u8 value[OTP_TA_VERION_BUF_LEN] = {0};
    hi_s32 ret;

    ret = otp_pv_item_read(field_name, value, &length);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_pv_item_read, ret);
        goto out;
    }

    if (length > OTP_TA_VERSION_LEN) {
        ret = HI_ERR_OTP_INVALID_LENGTH;
        goto out;
    }

    for (i = 0; i < length; i++) {
        if (value[i] != 0xff) {
            value[i] |= 1 << __otp_bit_count(value[i]);
            break;
        }
    }

    ret = otp_pv_item_write(field_name, value, length);

out:
    return ret;
}

static hi_s32 __otp_set_ta_certificate_version(const hi_char *field_name, const hi_u32 out_version)
{
    hi_s32 ret;
    hi_u32 version_from_otp = 0;
    hi_u32 i;

    ret = __otp_count_version_num(field_name, OTP_TA_CERT_VERSION_LEN, &version_from_otp);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_count_version_num, ret);
        goto out;
    }

    if (version_from_otp > out_version) {
        print_err_code(HI_ERR_OTP_FAILED_CHECKVERSION);
        ret = HI_ERR_OTP_FAILED_CHECKVERSION;
        goto out;
    }

    for (i = 0; i < (out_version - version_from_otp); i++) {
        ret = __otp_set_version_num(field_name, OTP_TA_CERT_VERSION_LEN);
        if (ret != HI_SUCCESS) {
            print_err_func(__otp_set_version_num, ret);
            goto out;
        }
    }

out:
    return ret;
}

static hi_s32 __otp_get_ta_certificate_version(const hi_char *field_name, hi_u32 *out_version)
{
    hi_s32 ret;
    hi_u32 version = 0;

    ret = __otp_count_version_num(field_name, OTP_TA_CERT_VERSION_LEN, &version);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_count_version_num, ret);
        goto out;
    }

    *out_version = version;

out:
    return ret;
}

static hi_s32 __otp_set_ta_secure_version(const hi_char *field_name, hi_u32 out_version)
{
    hi_s32 ret;
    hi_u32 version_from_otp = 0;
    hi_u32 i;

    hi_dbg_func_enter();

    ret = __otp_count_version_num(field_name, OTP_TA_VERSION_LEN, &version_from_otp);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_count_version_num, ret);
        goto out;
    }

    if (version_from_otp > out_version) {
        print_err_code(HI_ERR_OTP_FAILED_CHECKVERSION);
        ret = HI_ERR_OTP_FAILED_CHECKVERSION;
        goto out;
    }

    for (i = 0; i < (out_version - version_from_otp); i++) {
        ret = __otp_set_version_num(field_name, OTP_TA_VERSION_LEN);
        if (ret != HI_SUCCESS) {
            print_err_func(__otp_set_version_num, ret);
            goto out;
        }
    }

out:
    return ret;
}

static hi_s32 __otp_get_ta_secure_version(const hi_char *field_name, hi_u32 *out_version)
{
    hi_s32 ret;
    hi_u32 version = 0;

    ret = __otp_count_version_num(field_name, OTP_TA_VERSION_LEN, &version);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(__otp_count_version_num, ret);
        goto out;
    }

    *out_version = version;

out:
    return ret;
}

hi_s32 hi_tee_otp_get_sec_version(hi_u32 *version)
{
    struct hi_otp_field_name *field = __get_otp_field_name();
    hi_s32 ret;
    struct pv_item pv = {
        0x10, {0},
    };
    hi_u32 tmp_version = 0;
    hi_u32 i;

    if (version == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = otp_pv_item_read((const hi_char *)field->tee_secversion, pv.value, &pv.value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_pv_item_read, ret);
        goto out;
    }

    for (i = 0; i < pv.value_len; i++) {
        tmp_version += __otp_bit_count(pv.value[i]);
    }

    *version = tmp_version;

out:
    return ret;
}

static hi_s32 __otp_get_certificate_version_field(hi_tee_otp_ta_index index, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (index) {
        case HI_TEE_OTP_TA_INDEX_1:
            *field_id = field->ta1_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_2:
            *field_id = field->ta2_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_3:
            *field_id = field->ta3_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_4:
            *field_id = field->ta4_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_5:
            *field_id = field->ta5_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_6:
            *field_id = field->ta6_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_7:
            *field_id = field->ta7_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_8:
            *field_id = field->ta8_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_9:
            *field_id = field->ta9_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_10:
            *field_id = field->ta10_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_11:
            *field_id = field->ta11_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_12:
            *field_id = field->ta12_cert_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_13:
            *field_id = field->ta13_cert_secversion_ref;
            return HI_SUCCESS;
        default:
            break;
    }

    return HI_ERR_OTP_INVALID_PARA;
}

hi_s32 hi_tee_otp_set_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 version)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;

    if (index >= HI_TEE_OTP_TA_INDEX_MAX) {
        print_err_hex2((index >= HI_TEE_OTP_TA_INDEX_MAX), index);
        ret = HI_ERR_OTP_INVALID_PARA;
        goto out;
    }

    ret = __otp_get_certificate_version_field(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_certificate_version_field, ret);
        goto out;
    }

    ret = __otp_set_ta_certificate_version((const hi_char *)field_id, version);

out:
    return ret;
}

hi_s32 hi_tee_otp_get_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 *version)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;

    if (index >= HI_TEE_OTP_TA_INDEX_MAX) {
        print_err_hex2(index >= HI_TEE_OTP_TA_INDEX_MAX, index);
        ret = HI_ERR_OTP_INVALID_PARA;
        goto out;
    }

    if (version == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = __otp_get_certificate_version_field(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_certificate_version_field, ret);
        goto out;
    }

    ret = __otp_get_ta_certificate_version((const hi_char *)field_id, version);

out:
    return ret;
}

static hi_s32 __otp_get_version_field(hi_tee_otp_ta_index index, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (index) {
        case HI_TEE_OTP_TA_INDEX_1:
            *field_id = field->ta1_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_2:
            *field_id = field->ta2_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_3:
            *field_id = field->ta3_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_4:
            *field_id = field->ta4_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_5:
            *field_id = field->ta5_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_6:
            *field_id = field->ta6_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_7:
            *field_id = field->ta7_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_8:
            *field_id = field->ta8_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_9:
            *field_id = field->ta9_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_10:
            *field_id = field->ta10_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_11:
            *field_id = field->ta11_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_12:
            *field_id = field->ta12_secversion_ref;
            return HI_SUCCESS;
        case HI_TEE_OTP_TA_INDEX_13:
            *field_id = field->ta13_secversion_ref;
            return HI_SUCCESS;
        default:
            break;
    }

    return HI_ERR_OTP_INVALID_PARA;
}

hi_s32 hi_tee_otp_set_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 version)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;

    if (index >= HI_TEE_OTP_TA_INDEX_MAX) {
        print_err_hex2(index >= HI_TEE_OTP_TA_INDEX_MAX, index);
        ret = HI_ERR_OTP_INVALID_PARA;
        goto out;
    }

    ret = __otp_get_version_field(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_version_field, ret);
        goto out;
    }

    ret = __otp_set_ta_secure_version((const hi_char *)field_id, version);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_set_ta_secure_version, ret);
        goto out;
    }

out:
    return ret;
}

hi_s32 hi_tee_otp_get_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 *version)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;

    if (index >= HI_TEE_OTP_TA_INDEX_MAX) {
        print_err_hex2(index >= HI_TEE_OTP_TA_INDEX_MAX, index);
        ret = HI_ERR_OTP_INVALID_PARA;
        goto out;
    }

    if (version == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = __otp_get_version_field(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_version_field, ret);
        goto out;
    }

    ret = __otp_get_ta_secure_version((const hi_char *)field_id, version);

out:
    return ret;
}

static hi_s32 __otp_get_ta_msid_field_id(hi_tee_otp_ta_index index, hi_char **field_id)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    switch (index) {
        case HI_TEE_OTP_TA_INDEX_1:
            *field_id = field->ta1_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_2:
            *field_id = field->ta2_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_3:
            *field_id = field->ta3_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_4:
            *field_id = field->ta4_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_5:
            *field_id = field->ta5_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_6:
            *field_id = field->ta6_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_7:
            *field_id = field->ta7_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_8:
            *field_id = field->ta8_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_9:
            *field_id = field->ta9_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_10:
            *field_id = field->ta10_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_11:
            *field_id = field->ta11_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_12:
            *field_id = field->ta12_id_and_smid;
            break;
        case HI_TEE_OTP_TA_INDEX_13:
            *field_id = field->ta13_id_and_smid;
            break;
        default:
            return HI_ERR_OTP_INVALID_PARA;
    }
    return HI_SUCCESS;
}

static hi_s32 __otp_taid_msid_duplicate(hi_tee_otp_ta_index index, hi_u32 taid, hi_u32 msid)
{
    hi_s32 ret;
    hi_u32 i;
    hi_u32 ta_id;
    hi_u32 ms_id;

    for (i = 0; i < HI_TEE_OTP_TA_INDEX_MAX; i++) {
        ret = hi_tee_otp_get_taid_and_msid((hi_tee_otp_ta_index)i, &ta_id, &ms_id);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        if (taid == ta_id) {
            print_err_hex4(index, i, ta_id, ms_id);
            return HI_ERR_OTP_DUPLICATE_TAID;
        }
    }
    ret = hi_tee_otp_get_taid_and_msid(index, &ta_id, &ms_id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if ((ta_id != 0) || (ms_id != 0)) {
        print_err_hex2(ta_id, ms_id);
        return HI_ERR_OTP_TAID_SETED;
    }
    return HI_SUCCESS;
}

hi_s32 hi_tee_otp_set_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 taid, hi_u32 msid)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;
    struct pv_item pv = {
        0x08, {0x0},
    };
    hi_u8 *p = pv.value;

    if (index >= HI_TEE_OTP_TA_INDEX_MAX || taid == 0) {
        print_err_hex2(index, taid);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_taid_msid_duplicate(index, taid, msid);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_taid_msid_duplicate, ret);
        return ret;
    }

    ret = __otp_get_ta_msid_field_id(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_ta_msid_field_id, ret);
        return ret;
    }
    u32tou8(taid, p);
    p += 0x4;
    u32tou8(msid, p);

    return otp_pv_item_write((const hi_char *)field_id, pv.value, pv.value_len);
}

hi_s32 hi_tee_otp_get_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 *taid, hi_u32 *msid)
{
    hi_s32 ret;
    hi_char *field_id = HI_NULL;
    struct pv_item pv = {
        0x08, {0x0},
    };
    hi_u8 *p = pv.value;

    if (taid == HI_NULL || msid == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (index >= HI_TEE_OTP_TA_INDEX_MAX) {
        print_err_hex2((index >= HI_TEE_OTP_TA_INDEX_MAX), index);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = __otp_get_ta_msid_field_id(index, &field_id);
    if (ret != HI_SUCCESS) {
        print_err_func(__otp_get_ta_msid_field_id, ret);
        return ret;
    }

    ret = otp_pv_item_read((const hi_char *)field_id, pv.value, &pv.value_len);
    u8tou32(p, *taid);
    p += 0x4;
    u8tou32(p, *msid);
    return HI_SUCCESS;
}

hi_s32 hi_tee_otp_get_ta_index(hi_u32 taid, hi_tee_otp_ta_index *index)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;
    struct pv_item pv = {
        0x08, {0x0},
    };
    hi_tee_otp_ta_index tmp_index;
    hi_u32 tmp_taid;

    if (index == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    for (tmp_index = HI_TEE_OTP_TA_INDEX_1; tmp_index < HI_TEE_OTP_TA_INDEX_MAX; tmp_index++) {
        ret = __otp_get_ta_msid_field_id(tmp_index, &field_id);
        if (ret != HI_SUCCESS) {
            print_err_func(__otp_get_ta_msid_field_id, ret);
            goto out;
        }

        ret = otp_pv_item_read((const hi_char *)field_id, pv.value, &pv.value_len);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_pv_item_read, ret);
            goto out;
        }

        u8tou32(pv.value, tmp_taid);

        if (tmp_taid == taid) {
            *index = tmp_index;
            goto out;
        }
    }

    *index = HI_TEE_OTP_TA_INDEX_MAX;

    ret = HI_TEE_ERR_INVALID_TAID;
out:
    return ret;
}

hi_s32 hi_tee_otp_get_available_ta_index(hi_tee_otp_ta_index *index)
{
    hi_char *field_id = HI_NULL;
    hi_s32 ret;
    struct pv_item pv = {
        0x08, {0x0},
    };
    hi_tee_otp_ta_index tmp_index;
    hi_u32 tmp_taid = 0;

    if (index == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    for (tmp_index = HI_TEE_OTP_TA_INDEX_1; tmp_index < HI_TEE_OTP_TA_INDEX_MAX; tmp_index++) {
        ret = __otp_get_ta_msid_field_id(tmp_index, &field_id);
        if (ret != HI_SUCCESS) {
            print_err_func(__otp_get_ta_msid_field_id, ret);
            goto out;
        }

        ret = otp_pv_item_read((const hi_char *)field_id, pv.value, &pv.value_len);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_pv_item_read, ret);
            goto out;
        }

        u8tou32(pv.value, tmp_taid);

        if (tmp_taid == 0) {
            *index = tmp_index;
            goto out;
        }
    }

    *index = HI_TEE_OTP_TA_INDEX_MAX;

    ret = HI_TEE_ERR_INVALID_TAID;
out:
    return ret;
}

hi_s32 hi_tee_otp_get_priv_drm_data(hi_u32 offset, hi_u8 *data, hi_u32 *data_len)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    return otp_pv_item_read_off((const hi_char *)field->drm_key, offset, data, data_len);
}

hi_s32 hi_tee_otp_set_priv_drm_data(hi_u32 offset, const hi_u8 *data, hi_u32 data_len)
{
    struct hi_otp_field_name *field = __get_otp_field_name();

    return otp_pv_item_write_off((const hi_char *)field->drm_key, offset, data, data_len);
}

hi_s32 hi_tee_otp_get_runtime_check_stat(hi_bool *enable)
{
    struct hi_otp_field_name *field = __get_otp_field_name();
    hi_s32 ret;
    struct pv_item pv = {
        0x01, {0x0},
    };

    if (enable == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = otp_pv_item_read((const hi_char *)field->runtime_check_en, pv.value, &pv.value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_pv_item_read, ret);
        goto out;
    }

    *enable = ((pv.value[0] & RUNTIME_CHECK_EN) == RUNTIME_CHECK_EN) ? HI_TRUE : HI_FALSE;

out:
    return ret;
}

hi_s32 hi_tee_otp_enable_runtime_check(hi_void)
{
    struct hi_otp_field_name *field = __get_otp_field_name();
    struct pv_item pv = {
        0x01, {0x1},
    };

    return otp_pv_item_write((const hi_char *)field->runtime_check_en, pv.value, pv.value_len);
}

