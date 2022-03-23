/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:keyladder session node list manage.
 * Author: Hisilicon hisecurity team
 * Create: 2019-6-25
 */
#include "drv_klad_sw.h"

#include "securec.h"
#include "hi_tee_drv_klad.h"
#include "tee_drv_ioctl_klad.h"
#include "drv_klad_hw.h"
#include "drv_rkp.h"
#include "drv_rkp_reg.h"

typedef struct {
    hi_u32 cmd;
    hi_s32(*f_driver_cmd_process)(hi_void *arg, hi_u32 len);
} fmw_klad_ioctl_map;

typedef struct {
    hi_handle ks_handle;
    hi_klad_attr attr;
    hi_u32 level;
    hi_klad_session_key session_key[HI_SESSION_KEY_MAX_LEVEL];
    hi_klad_content_key content_key;
} klad_encrypt_key_param;

#define DRV_INSTANCE_SUPPORT_MAX   0x10
#define HI_TEE_KLAD_MAX_KEY_LEN    0x10
#define HISI_VENDOR_ID             0x0f000000

typedef struct {
    hi_mutex                lock;
    declare_bitmap(ins_bitmap, DRV_INSTANCE_SUPPORT_MAX);
    klad_encrypt_key_param ins[DRV_INSTANCE_SUPPORT_MAX];
} drv_klad_ins_mngt;


static hi_s32 __klad_gen_hkl_attr(hi_klad_attr *attr, struct klad_r_base_attr *base_attr)
{
    base_attr->klad_type = attr->klad_cfg.klad_type;
    base_attr->vendor_id = attr->klad_cfg.owner_id;
    if (attr->key_sec_cfg.key_sec == HI_KLAD_SEC_ENABLE) {
        base_attr->is_secure_key = HI_TRUE;
    } else {
        base_attr->is_secure_key = HI_FALSE;
    }
    return HI_SUCCESS;
}

static struct klad_r_base_attr g_module_id_list[] = {
#include "data/hi3751v900/module_id_basic.txt"
#ifdef HI_KLAD_NAGRA_SUPPORT
#include KLAD_MODULE_ID_NAGRA
#endif
};

/*
* If module_id list not provide rootkey slot information. should get from OTP fuse.
*/
static hi_s32 __klad_rk_slot_find(hi_rootkey_select *root_slot)
{
    return rkp_cas_slot_find(root_slot);
}


static hi_s32 __klad_generate_modid_rkslot(struct klad_r_base_attr *list, struct klad_r_base_attr *base_attr)
{
    hi_s32 ret;
    rkp_module_id_2 module_id;

    /*
    * If send non seucre key to REE, use ree module id(tee only bit is set 0).
    * must check TEE access only area is 0 and TEE_TPP_HPP access area is 0
    */
    module_id.u32 = list->module_id[0x2];
    if ((base_attr->is_secure_key == HI_FALSE) &&
        (module_id.tee.bits.tee_tee_only != 0) &&
        (module_id.tee.bits.tee_tee_tpp_hpp_access != 0)) {
        print_dbg_hex3(base_attr->is_secure_key, base_attr->module_id[0x1], HI_ERR_KLAD_RKP_INVALID_MODULE_ID);
        return HI_ERR_KLAD_RKP_INVALID_MODULE_ID;
    }

    base_attr->module_id[0x0] = list->module_id[0x0];
    base_attr->module_id[0x1] = list->module_id[0x1];
    base_attr->module_id[0x2] = list->module_id[0x2];
    base_attr->module_id[0x3] = list->module_id[0x3];
    base_attr->unique         = list->unique;
    if (list->root_slot >= HI_ROOTKEY_SLOT_MAX) {
        ret = __klad_rk_slot_find(&base_attr->root_slot);
    } else {
        base_attr->root_slot      = list->root_slot;
        ret = HI_SUCCESS;
    }
    print_dbg_hex4(base_attr->module_id[0x0], base_attr->module_id[0x1],
                   base_attr->module_id[0x2], base_attr->root_slot);
    return ret;
}

/*
* Keyladder Module id and rootkey slot generation.
*
* Module ID is 128 bits string.
* It is set to 4 32bits registers of logic.
* module_id[3] = bit[0~31]
* module_id[2] = bit[32~63]
* module_id[1] = bit[64~95]
* module_id[0] = bit[96~127]
*/
static hi_s32 __klad_com_gen_moduleid_rkslot(hi_klad_attr *attr, struct klad_r_base_attr *base_attr)
{
    hi_u32 index;
    hi_bool secure_key = attr->key_sec_cfg.key_sec == HI_KLAD_SEC_ENABLE ? HI_TRUE : HI_FALSE;

    hi_dbg_klad("get moduleid from global list.\n");
    print_dbg_hex3(attr->klad_cfg.klad_type, attr->klad_cfg.owner_id, attr->key_sec_cfg.key_sec);

    for (index = 0; index < sizeof(g_module_id_list) / sizeof(struct klad_r_base_attr); index++) {
        if (attr->klad_cfg.klad_type == g_module_id_list[index].klad_type &&
                attr->klad_cfg.owner_id == g_module_id_list[index].vendor_id &&
                secure_key == g_module_id_list[index].is_secure_key) {
            print_dbg_hex(index);
            return __klad_generate_modid_rkslot(&g_module_id_list[index], base_attr);
        }
    }
    for (index = 0; index < sizeof(g_module_id_list) / sizeof(struct klad_r_base_attr); index++) {
        if (attr->klad_cfg.klad_type == g_module_id_list[index].klad_type &&
                secure_key == g_module_id_list[index].is_secure_key &&
                g_module_id_list[index].vendor_id == 0) {
            print_dbg_hex(index);
            return __klad_generate_modid_rkslot(&g_module_id_list[index], base_attr);
        }
    }
    print_err_hex4(attr->klad_cfg.klad_type, attr->klad_cfg.owner_id,
                   attr->key_sec_cfg.key_sec, HI_ERR_KLAD_NOT_FIND_MODID);
    return HI_ERR_KLAD_NOT_FIND_MODID;
}

static hi_void __klad_dym_tee_moduleid(hi_rootkey_attr *rk_attr,
                                       rkp_module_id_0 *module_id0,
                                       rkp_module_id_1 *module_id1,
                                       rkp_module_id_2 *module_id2,
                                       rkp_module_id_3 *module_id3)
{
    module_id0->tee.bits.tee_decrypt = rk_attr->target_feature_support.decrypt_support;
    module_id0->tee.bits.tee_encrypt = rk_attr->target_feature_support.encrypt_support;
    module_id0->tee.bits.tee_content_key_mcipher = rk_attr->target_support.mcipher_support;
    module_id0->tee.bits.tee_content_key_tscipher = rk_attr->target_support.tscipher_support;
    module_id0->tee.bits.tee_destination_sm4 = rk_attr->target_alg_support.sm4_support;
    module_id0->tee.bits.tee_destination_tdes = rk_attr->target_alg_support.tdes_support;
    module_id0->tee.bits.tee_destination_aes = rk_attr->target_alg_support.aes_support;
    module_id0->tee.bits.tee_destination_csa3 = rk_attr->target_alg_support.csa3_support;
    module_id0->tee.bits.tee_destination_csa2 = rk_attr->target_alg_support.csa2_support;
    module_id0->tee.bits.tee_destination_multi2 = 0;
    module_id0->tee.bits.tee_destination_sm3_hmac = rk_attr->target_alg_support.hmac_sm3_support;
    module_id0->tee.bits.tee_destination_sha2_hmac = rk_attr->target_alg_support.hmac_sha_support;
    module_id0->tee.bits.tee_level_up = 0;
    module_id0->tee.bits.tee_stage = rk_attr->level;

    module_id1->tee.bits.tee_klad_aes = rk_attr->alg_support.aes_support;
    module_id1->tee.bits.tee_klad_tdes = rk_attr->alg_support.tdes_support;
    module_id1->tee.bits.tee_klad_sm4 = rk_attr->alg_support.sm4_support;
    module_id1->tee.bits.tee_klad_hkl = 1;
    module_id1->tee.bits.tee_no_restriction = 0;

    module_id2->tee.bits.tee_tee_only = 0;
    module_id2->tee.bits.tee_tee_tpp_hpp_access = 0;
    module_id2->tee.bits.tee_remap = 0;
    module_id2->tee.bits.tee_flash_prot_en = 0;
    module_id2->tee.bits.tee_allowed_nonce = 0;
    module_id2->tee.bits.tee_c2_checksum_en = 0;
    module_id2->tee.bits.tee_cm_checksum_en = 0;
    module_id2->tee.bits.tee_hdcp_rk = 0;

    module_id3->u32 = 0;
}

/* module id come from caller's rootkey attribute */
static hi_s32 __klad_dym_gen_moduleid(hi_rootkey_attr *rk_attr, struct klad_r_base_attr *base_attr)
{
    rkp_module_id_0 module_id0;
    rkp_module_id_1 module_id1;
    rkp_module_id_2 module_id2;
    rkp_module_id_3 module_id3;

    module_id0.u32 = 0;
    module_id1.u32 = 0;
    module_id2.u32 = 0;
    module_id3.u32 = 0;

    __klad_dym_tee_moduleid(rk_attr, &module_id0, &module_id1, &module_id2, &module_id3);

    base_attr->module_id[0x0] = module_id0.u32;
    base_attr->module_id[0x1] = module_id1.u32;
    base_attr->module_id[0x2] = module_id2.u32;
    base_attr->module_id[0x3] = module_id3.u32;

    return HI_SUCCESS;
}

static hi_s32 __klad_gen_rkp_attr(hi_rootkey_attr *rk_attr, hi_klad_attr *attr, struct klad_r_base_attr *base_attr)
{
    if (attr->klad_cfg.klad_type == HI_KLAD_TYPE_DYNAMIC) {
        base_attr->root_slot = rk_attr->rootkey_sel;
        return __klad_dym_gen_moduleid(rk_attr, base_attr);
    } else {
        return __klad_com_gen_moduleid_rkslot(attr, base_attr);
    }
}

static hi_s32 __klad_com_param_check_session(hi_klad_com_entry *entry, struct klad_r_base_attr *base_attr)
{
    hi_u32 ret = HI_SUCCESS;
    hi_u32 level_index;
    rkp_module_id_0 module_id0;
    hi_klad_level klad_level;

    module_id0.u32 = base_attr->module_id[0];
    klad_level =  module_id0.tee.bits.tee_stage;
    if (klad_level < HI_KLAD_LEVEL2) {
        return HI_SUCCESS;
    }

    /*
    * if first stage session key is not set, but second stage sesssin key seted,
    * the second stage session key will droped, because this is a illegal operation.
    */
    for (level_index = 0; level_index < HI_KLAD_LEVEL_MAX; level_index++) {
        if (entry->session_cnt[level_index] == 0) {
            break;
        }
    }

    /* At this time, level_index is equal to the keyladder stage. */
    if (level_index != klad_level) {
        print_err_hex2(level_index, klad_level);
        return HI_ERR_KLAD_INVALID_LEVEL;
    }

    return ret;
}

static hi_s32 __klad_com_param_check(hi_klad_com_entry *entry, struct klad_r_base_attr *base_attr)
{
    if (entry->target_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->attr_cnt == 0) {
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    if (__klad_com_param_check_session(entry, base_attr) != HI_SUCCESS) {
        return HI_ERR_KLAD_INVALID_LEVEL;
    }

    /*
    * keyladder stage in module id is not same as session key~, check failed.
    * NOTE:fp keyladder, 3 stage in module id.
    */
    return HI_SUCCESS;
}

static hi_s32 fmw_klad_com_startup(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_com_entry *entry = HI_NULL;
    struct klad_r_base_attr key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_com_entry)) {
        print_err_hex2(len, sizeof(hi_klad_com_entry));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    entry = (hi_klad_com_entry *)(arg);

    ret = __klad_gen_rkp_attr(&entry->rk_attr, &entry->attr, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_rkp_attr, ret);
        goto out;
    }

    ret = __klad_com_param_check(entry, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_param_check, ret);
        goto out;
    }

    dump_hkl_com(entry);

    ret = hi_drv_hw_com_klad_startup(entry->hw_handle, entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_com_klad_startup, ret);
    }
out:
    return ret;
}

static hi_s32 __klad_ta_param_check(hi_klad_ta_entry *entry)
{
    if (entry->target_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->attr_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->session_ta_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->trans_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->content_ta_cnt == 0) {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 fmw_klad_ta_startup(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_ta_entry *entry = HI_NULL;

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_ta_entry)) {
        print_err_hex2(len, sizeof(hi_klad_ta_entry));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    entry = (hi_klad_ta_entry *)(arg);

    ret = __klad_ta_param_check(entry);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_ta_param_check, ret);
        goto out;
    }

    ret = hi_drv_hw_ta_klad_startup(entry->hw_handle, entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_ta_klad_startup, ret);
    }
out:
    return ret;
}

static hi_s32 __klad_fp_param_check(hi_klad_fp_entry *entry)
{
    hi_u32 i;

    if (entry->target_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->attr_cnt == 0) {
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        /*
        * if first stage session key is not set, but second stage sesssin key seted,
        * the second stage session key will droped, because this is a illegal operation.
        */
        if (entry->session_cnt[i] == 0) {
            break;
        }
    }
    /*
    * keyladder stage in module id is not same as session key~, check failed.
    * NOTE:fp keyladder, 3 stage in module id.
    */
    return HI_SUCCESS;
}

static hi_s32 fmw_klad_fp_startup(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_fp_entry *entry = HI_NULL;

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_fp_entry)) {
        print_err_hex2(len, sizeof(hi_klad_fp_entry));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    entry = (hi_klad_fp_entry *)(arg);

    ret = __klad_fp_param_check(entry);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_fp_param_check, ret);
        goto out;
    }

    ret = hi_drv_hw_fp_klad_startup(entry->hw_handle, entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_fp_klad_startup, ret);
    }

out:
    return ret;
}

hi_s32 fmw_klad_fp_route(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    struct klad_entry_key key = {0};
    hi_klad_create_attr *hkl_attr = HI_NULL;

    if (len != sizeof(hi_klad_create_attr)) {
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    hkl_attr = (hi_klad_create_attr *)(arg);

    ret = __klad_com_gen_moduleid_rkslot(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_gen_moduleid_rkslot, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    ret = hi_drv_hw_fp_klad_route(&key);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_fp_klad_route, ret);
    }

out:
    return ret;
}

static hi_s32 __klad_nonce_param_check(hi_klad_nonce_entry *entry)
{
    if (entry->target_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->attr_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->session_cnt[0] == 0) {
        return HI_FAILURE;
    }
    if (entry->nonce_cnt == 0) {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 fmw_klad_nonce_startup(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_nonce_entry *entry = HI_NULL;

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_nonce_entry)) {
        print_err_hex2(len, sizeof(hi_klad_nonce_entry));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    entry = (hi_klad_nonce_entry *)(arg);

    ret = __klad_nonce_param_check(entry);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_nonce_param_check, ret);
        goto out;
    }

    ret = hi_drv_hw_nonce_klad_startup(entry->hw_handle, entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_nonce_klad_startup, ret);
    }
out:
    return ret;
}

static hi_s32 __klad_clr_param_check(hi_klad_clr_entry *entry)
{
    if (entry->target_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->attr_cnt == 0) {
        return HI_FAILURE;
    }
    if (entry->clr_cnt == 0) {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 fmw_klad_clr_process(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_clr_entry *entry = HI_NULL;
    struct klad_entry_key key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_clr_entry)) {
        print_err_hex2(len, sizeof(hi_klad_clr_entry));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    entry = (hi_klad_clr_entry *)(arg);

    ret = __klad_clr_param_check(entry);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_nonce_param_check, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&entry->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    dump_hkl_attr(&key.hkl_base_attr);
    dump_hkl_clr_route(entry);

    ret = hi_drv_hw_clr_route_process(&key, entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_clr_route_process, ret);
    }
out:
    return ret;
}

static hi_s32 fmw_klad_com_create(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_create_attr *hkl_attr = HI_NULL;
    struct klad_entry_key key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_create_attr)) {
        print_err_hex2(len, sizeof(hi_klad_create_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    hkl_attr = (hi_klad_create_attr *)(arg);

    ret = __klad_gen_rkp_attr(&hkl_attr->rk_attr, &hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_rkp_attr, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    dump_hkl_attr(&key.hkl_base_attr);
    dump_hkl_create_attr(hkl_attr);

    ret = hi_drv_hw_com_klad_create(&hkl_attr->hw_handle, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_com_klad_create, ret);
    }
out:
    return ret;
}

static hi_s32 fmw_klad_ta_create(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_create_attr *hkl_attr = HI_NULL;
    struct klad_entry_key key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_create_attr)) {
        print_err_hex2(len, sizeof(hi_klad_create_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    hkl_attr = (hi_klad_create_attr *)(arg);

    ret = __klad_com_gen_moduleid_rkslot(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_gen_moduleid_rkslot, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    ret = hi_drv_hw_ta_klad_create(&hkl_attr->hw_handle, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_ta_klad_create, ret);
    }
out:
    return ret;
}

static hi_s32 fmw_klad_fp_create(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_create_attr *hkl_attr = HI_NULL;
    struct klad_entry_key key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_create_attr)) {
        print_err_hex2(len, sizeof(hi_klad_create_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    hkl_attr = (hi_klad_create_attr *)(arg);

    ret = __klad_com_gen_moduleid_rkslot(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_gen_moduleid_rkslot, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    ret = hi_drv_hw_fp_klad_create(&hkl_attr->hw_handle, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_fp_klad_create, ret);
    }

out:
    return ret;
}

static hi_s32 fmw_klad_nonce_create(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_klad_create_attr *hkl_attr = HI_NULL;
    struct klad_entry_key key = {0};

    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_klad_create_attr)) {
        print_err_hex2(len, sizeof(hi_klad_create_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    hkl_attr = (hi_klad_create_attr *)(arg);

    ret = __klad_com_gen_moduleid_rkslot(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_gen_moduleid_rkslot, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&hkl_attr->attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    ret = hi_drv_hw_nonce_klad_create(&hkl_attr->hw_handle, &key);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_nonce_klad_create, ret);
    }
out:
    return ret;
}
static hi_s32 fmw_klad_com_destroy(hi_void *arg, hi_u32 len)
{
    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_handle)) {
        print_err_hex2(len, sizeof(hi_handle));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_drv_hw_com_klad_destroy(*(hi_handle *)(arg));
}

static hi_s32 fmw_klad_ta_destroy(hi_void *arg, hi_u32 len)
{
    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_handle)) {
        print_err_hex2(len, sizeof(hi_handle));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_drv_hw_ta_klad_destroy(*(hi_handle *)(arg));
}

static hi_s32 fmw_klad_fp_destroy(hi_void *arg, hi_u32 len)
{
    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_handle)) {
        print_err_hex2(len, sizeof(hi_handle));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_drv_hw_fp_klad_destroy(*(hi_handle *)(arg));
}

static hi_s32 fmw_klad_nonce_destroy(hi_void *arg, hi_u32 len)
{
    if (arg == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (len != sizeof(hi_handle)) {
        print_err_hex2(len, sizeof(hi_handle));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_drv_hw_nonce_klad_destroy(*(hi_handle *)(arg));
}

static fmw_klad_ioctl_map g_klad_common_handle[] = {
    /* common klad */
    { CMD_KLAD_COM_CREATE,         fmw_klad_com_create },
    { CMD_KLAD_COM_STARTUP,        fmw_klad_com_startup },
    { CMD_KLAD_COM_DESTORY,        fmw_klad_com_destroy },
    /* clear klad */
    { CMD_KLAD_CLR_PROCESS,        fmw_klad_clr_process },
    /* ta klad */
    { CMD_KLAD_TA_CREATE,          fmw_klad_ta_create },
    { CMD_KLAD_TA_STARTUP,         fmw_klad_ta_startup },
    { CMD_KLAD_TA_DESTORY,         fmw_klad_ta_destroy },
    /* fp klad */
    { CMD_KLAD_FP_CREATE,          fmw_klad_fp_create },
    { CMD_KLAD_FP_STARTUP,         fmw_klad_fp_startup },
    { CMD_KLAD_FP_CRYPTO,          fmw_klad_fp_startup },
    { CMD_KLAD_FP_ROUTE,           fmw_klad_fp_route },
    { CMD_KLAD_FP_DESTORY,         fmw_klad_fp_destroy },
    /* nonce klad */
    { CMD_KLAD_NONCE_CREATE,       fmw_klad_nonce_create },
    { CMD_KLAD_NONCE_STARTUP,      fmw_klad_nonce_startup },
    { CMD_KLAD_NONCE_DESTORY,      fmw_klad_nonce_destroy },

    { CMD_KLAD_MAX,                HI_NULL }
};

hi_s32 fmw_klad_ioctl(unsigned int cmd, hi_void *arg, hi_u32 len)
{
    hi_s32 ret = HI_ERR_KLAD_IOCTL_CMD_INVALID;
    hi_u32 size;
    fmw_klad_ioctl_map *node = HI_NULL_PTR;
    struct time_ns time_b;

    timestamp(&time_b);
    for (size = 0, node = &g_klad_common_handle[0];
         size < sizeof(g_klad_common_handle) / sizeof(g_klad_common_handle[0]);
         size++, node = &g_klad_common_handle[size]) {
        if (node->cmd != cmd) {
            print_dbg_hex(node->cmd);
            continue;
        }
        if (node->f_driver_cmd_process != HI_NULL) {
            ret = node->f_driver_cmd_process(arg, len);
        } else {
            ret = HI_ERR_KLAD_IOCTL_FUNC_NULL;
        }
        break;
    }
    if (ret != HI_SUCCESS) {
        print_err_hex(cmd);
        print_err_code(ret);
    }

    get_curr_cost("drv cmd", &time_b);
    return ret;
}

hi_s32 hi_drv_klad_clear_cw(const klad_clear_cw_param *clear_cw)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    hi_klad_clr_entry entry = {0};
    struct klad_entry_key key = {0};

    if (clear_cw == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    entry.target_cnt = 1;
    entry.target_handle = clear_cw->ks_handle;

    entry.attr_cnt = 1;
    if (memcpy_s(&entry.attr, sizeof(hi_klad_attr), &clear_cw->attr, sizeof(clear_cw->attr)) != HI_SUCCESS) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.clr_cnt = 1;
    if (memcpy_s(&entry.clr_key, sizeof(hi_klad_clear_key),
                 &clear_cw->clr_key, sizeof(clear_cw->clr_key)) != HI_SUCCESS) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    ret = __klad_gen_hkl_attr(&entry.attr, &key.hkl_base_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_gen_hkl_attr, ret);
        goto out;
    }

    dump_hkl_attr(&key.hkl_base_attr);
    dump_hkl_clr_route(&entry);

    ret = hi_drv_hw_clr_route_process(&key, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_drv_hw_clr_route_process, ret);
    }
out:
    return ret;
}

hi_s32 hi_drv_klad_clear_iv(const klad_clear_iv_param *clr_iv)
{
    if (clr_iv == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (is_invalid_ks_handle(clr_iv->ks_handle)) {
        print_err_code(HI_ERR_KLAD_INVALID_PARAM);
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_drv_hw_clr_iv_process(clr_iv);
}

static hi_s32 __klad_com_start_prepare(const klad_encrypt_key_param *klad_cfg, hi_klad_com_entry *entry)
{
    hi_u32 i;
    errno_t errno;
    hi_s32 ret = HI_SUCCESS;

    entry->target_cnt = 0x1;
    entry->target_handle = klad_cfg->ks_handle;

    entry->attr_cnt = 0x1;
    errno = memcpy_s(&entry->attr, sizeof(hi_klad_attr), &klad_cfg->attr, sizeof(klad_cfg->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry->content_cnt = 0x1;
    errno = memcpy_s(&entry->content_key, sizeof(hi_klad_content_key),
                     &klad_cfg->content_key, sizeof(klad_cfg->content_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out;
    }

    if (klad_cfg->level < HI_KLAD_LEVEL2) {
        goto out;
    }
    for (i = 0; i < (klad_cfg->level - 0x1); i++) {
        entry->session_cnt[i] = 0x1;
        errno = memcpy_s(&entry->session_key[i], sizeof(hi_klad_session_key),
                         &klad_cfg->session_key[i], sizeof(klad_cfg->session_key[i]));
        if (errno != EOK) {
            ret = HI_ERR_KLAD_SEC_FAILED;
            print_err_func(memcpy_s, ret);
            goto out;
        }
    }

out:
    return ret;
}

static hi_s32 __klad_encrypt_key(const klad_encrypt_key_param *klad_cfg)
{
    hi_s32 ret;
    errno_t errno;
    hi_klad_create_attr hkl_attr = {0};
    hi_klad_com_entry entry = {0};

    errno = memcpy_s(&hkl_attr.attr, sizeof(hkl_attr.attr), &klad_cfg->attr, sizeof(klad_cfg->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out0;
    }

    ret = fmw_klad_com_create(&hkl_attr, sizeof(hi_klad_create_attr));
    if (ret != HI_SUCCESS) {
        print_err_func(fmw_klad_com_create, ret);
        goto out0;
    }
    ret = __klad_com_start_prepare(klad_cfg, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_com_start_prepare, ret);
        goto out1;
    }
    entry.hw_handle = hkl_attr.hw_handle;
    ret = fmw_klad_com_startup(&entry,  sizeof(hi_klad_com_entry));
    if (ret != HI_SUCCESS) {
        print_err_func(fmw_klad_com_startup, ret);
        goto out1;
    }

out1:
    ret = fmw_klad_com_destroy(&hkl_attr.hw_handle, sizeof(hkl_attr.hw_handle));
    if (ret != HI_SUCCESS) {
        print_err_func(fmw_klad_com_destroy, ret);
    }
out0:
    return ret;
}

static drv_klad_ins_mngt g_drv_hkl = {
    .lock       = __mutex_initializer(g_drv_hkl.lock),
    .ins        = {{0}},
};

drv_klad_ins_mngt* get_drv_hkl_ins(hi_void)
{
    return &g_drv_hkl;
}

hi_void hi_tee_drv_hkl_ins_init(hi_void)
{
    bitmap_zero(g_drv_hkl.ins_bitmap, DRV_INSTANCE_SUPPORT_MAX);
}

hi_s32 hi_tee_drv_klad_creat(hi_handle *handle)
{
    hi_u32 id;
    hi_s32 ret = HI_SUCCESS;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        print_err_code(ret);
        goto out0;
    }

    __mutex_lock(&ins_mngt->lock);
    id = find_first_zero_bit(ins_mngt->ins_bitmap, DRV_INSTANCE_SUPPORT_MAX);
    if (id >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_NO_RESOURCE;
        print_err_func(find_first_zero_bit, ret);
        goto out1;
    }

    set_bit(id, ins_mngt->ins_bitmap);
    *handle = id;

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

hi_s32 hi_tee_drv_klad_destroy(hi_handle handle)
{
    errno_t errno;
    hi_s32 ret = HI_SUCCESS;;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out0;
    }

    __mutex_lock(&ins_mngt->lock);
    errno = memset_s(&ins_mngt->ins[handle], sizeof(klad_encrypt_key_param), 0x0, sizeof(ins_mngt->ins[handle]));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memset_s, ret);
        goto out1;
    }

    clear_bit(handle, ins_mngt->ins_bitmap);

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

hi_s32 hi_tee_drv_klad_attach(hi_handle handle, hi_handle target)
{
    hi_s32 ret = HI_SUCCESS;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out;
    }

    __mutex_lock(&ins_mngt->lock);
    ins_mngt->ins[handle].ks_handle = target;
    __mutex_unlock(&ins_mngt->lock);

out:
    return ret;
}

hi_s32 hi_tee_drv_klad_detach(hi_handle handle, hi_handle target)
{
    hi_s32 ret = HI_SUCCESS;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out;
    }

    __mutex_lock(&ins_mngt->lock);
    if (ins_mngt->ins[handle].ks_handle == target) {
        ins_mngt->ins[handle].ks_handle = 0x0;
    }
    __mutex_unlock(&ins_mngt->lock);

out:
    return ret;
}

hi_s32 hi_tee_drv_klad_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    errno_t errno;
    hi_s32 ret = HI_SUCCESS;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out0;
    }

    if (attr == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        print_err_code(ret);
        goto out0;
    }

    if (attr->klad_cfg.klad_type == HI_KLAD_TYPE_SECSTORGE) {
        if (attr->klad_cfg.owner_id != HISI_VENDOR_ID) {
            ret = HI_ERR_KLAD_INVALID_PARAM;
            print_err_hex(attr->klad_cfg.owner_id);
            goto out0;
        }
    }

    __mutex_lock(&ins_mngt->lock);

    errno = memcpy_s(&ins_mngt->ins[handle].attr, sizeof(hi_klad_attr), attr, sizeof(*attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out1;
    }

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

hi_s32 hi_tee_drv_klad_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    errno_t errno;
    hi_s32 ret = HI_SUCCESS;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out0;
    }

    if (attr == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        print_err_code(ret);
        goto out0;
    }
    __mutex_lock(&ins_mngt->lock);

    errno = memcpy_s(attr, sizeof(*attr), &ins_mngt->ins[handle].attr, sizeof(hi_klad_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out1;
    }

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

hi_s32 hi_tee_drv_klad_set_session_key(hi_handle handle, const hi_klad_session_key *key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;
    hi_klad_session_key *session_key = HI_NULL;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out0;
    }

    if (key == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        print_err_code(ret);
        goto out0;
    }

    __mutex_lock(&ins_mngt->lock);

    session_key = &ins_mngt->ins[handle].session_key[key->level];
    errno = memcpy_s(session_key, sizeof(*session_key), key, sizeof(*key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out1;
    }

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

hi_s32 hi_tee_drv_klad_set_content_key(hi_handle handle, const hi_klad_content_key *key)
{
    hi_s32 ret;
    errno_t errno;
    drv_klad_ins_mngt *ins_mngt = get_drv_hkl_ins();

    if (handle >= DRV_INSTANCE_SUPPORT_MAX) {
        ret = HI_ERR_KLAD_INVALID_HANDLE;
        print_err_code(ret);
        goto out0;
    }

    if (key == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        print_err_code(ret);
        goto out0;
    }

    __mutex_lock(&ins_mngt->lock);

    errno = memcpy_s(&ins_mngt->ins[handle].content_key, sizeof(hi_klad_content_key), key, sizeof(*key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out1;
    }

    ret = __klad_encrypt_key(&ins_mngt->ins[handle]);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_encrypt_key, ret);
    }

out1:
    __mutex_unlock(&ins_mngt->lock);
out0:
    return ret;
}

