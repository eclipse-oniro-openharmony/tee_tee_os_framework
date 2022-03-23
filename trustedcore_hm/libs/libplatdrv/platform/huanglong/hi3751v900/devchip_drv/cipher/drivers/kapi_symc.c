/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: drivers of kapi_symc
 * Author: zhaoguihong
 * Create: 2019-06-18
 */
#include "drv_osal_lib.h"
#include "cryp_symc.h"
#include "drv_cenc.h"
#include "hi_tee_drv_keyslot.h"

/* max number of nodes */
#define MAX_PKG_NUMBER 100000

/* max length of CCM/GCM AAD */
#define MAX_AEAD_A_LEN 0x100000

typedef struct {
    hi_u32 open : 1;   /* !<  open or close */
    hi_u32 config : 1; /* !<  aleardy config or not */
    symc_func *func;
    void *cryp_ctx;      /* !<  Context of cryp instance */
    crypto_owner owner;  /* !<  user ID */
    hi_cipher_ctrl ctrl; /* !<  control infomation */
    hi_u32 key_slot;
} kapi_symc_ctx;

/* ! Context of cipher */
static kapi_symc_ctx *g_kapi_ctx = HI_NULL;

/* symc mutex */
static crypto_mutex g_symc_mutex;

static hi_s32 kapi_symc_check_handle(hi_u32 handle)
{
    if ((HI_HANDLE_GET_MODID(handle) != HI_ID_CIPHER) || (HI_HANDLE_GET_PriDATA(handle) != 0)) {
        hi_log_error("Invalid handle 0x%x!\n", handle);
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }

    if (HI_HANDLE_GET_CHNID(handle) >= CRYPTO_HARD_CHANNEL_MAX) {
        hi_log_error("chan %d is too large, max: %d\n", HI_HANDLE_GET_CHNID(handle), CRYPTO_HARD_CHANNEL_MAX);
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }

    if (g_kapi_ctx[HI_HANDLE_GET_CHNID(handle)].open == HI_FALSE) {
        hi_log_error("chan %d is not open\n", HI_HANDLE_GET_CHNID(handle));
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }

    return HI_SUCCESS;
}

static hi_s32 kapi_symc_lock()
{
    hi_s32 ret;

    ret = crypto_mutex_lock(&g_symc_mutex);
    if (ret != HI_SUCCESS) {
        hi_log_error("error, symc lock failed\n");
        hi_log_print_func_err(crypto_mutex_lock, ret);
    }

    return ret;
}

#define kapi_symc_unlock()  crypto_mutex_unlock(&g_symc_mutex)
#define AES_CCM_MIN_TAG_LEN 4
#define AES_CCM_MAX_TAG_LEN 16
#define AES_GCM_MIN_TAG_LEN 1
#define AES_GCM_MAX_TAG_LEN 16

/** @} */ /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      symc */
/** @{ */ /** <!-- [kapi] */

hi_s32 kapi_symc_init(void)
{
    hi_s32 ret;

    hi_log_info("kapi_symc_init()\n");

    hi_log_func_enter();

    crypto_mutex_init(&g_symc_mutex);

    g_kapi_ctx = crypto_calloc(sizeof(kapi_symc_ctx), CRYPTO_HARD_CHANNEL_MAX);
    if (g_kapi_ctx == HI_NULL) {
        hi_log_print_func_err(crypto_calloc, HI_ERR_CIPHER_FAILED_MEM);
        return HI_ERR_CIPHER_FAILED_MEM;
    }

    ret = cryp_symc_init();
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(cryp_symc_init, ret);
        crypto_free(g_kapi_ctx);
        g_kapi_ctx = HI_NULL;
        return ret;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_deinit(void)
{
    hi_log_info("kapi_symc_deinit()\n");

    hi_log_func_enter();

    cryp_symc_deinit();

    crypto_mutex_destroy(&g_symc_mutex);
    crypto_free(g_kapi_ctx);
    g_kapi_ctx = HI_NULL;

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_release(void)
{
    hi_u32 i = 0;
    hi_u32 chn;
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    crypto_owner owner;

    hi_log_func_enter();

    crypto_get_owner(&owner);

    /* destroy the channel which are created by current user */
    for (i = 0; i < CRYPTO_HARD_CHANNEL_MAX; i++) {
        ctx = &g_kapi_ctx[i];
        if (ctx->open == HI_TRUE) {
            if (memcmp(&owner, &ctx->owner, sizeof(owner)) == 0) {
                chn = HI_HANDLE_MAKEHANDLE(HI_ID_CIPHER, 0, i);
                hi_log_info("[SYMC] release chn %d, owner 0x%x\n", chn, owner);
                ret = kapi_symc_destroy(chn);
                if (ret != HI_SUCCESS) {
                    hi_log_print_func_err(kapi_symc_destroy, ret);
                    return ret;
                }
            }
        }
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

static hi_s32 kapi_symc_alloc_keyslot(hi_u32 *slot_num)
{
    hi_s32 ret;

    ret = hi_drv_ks_create(HI_KEYSLOT_TYPE_MCIPHER, slot_num);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_drv_ks_create, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 kapi_symc_free_keyslot(hi_u32 slot_num)
{
    hi_s32 ret;

    ret = hi_drv_ks_destory(HI_KEYSLOT_TYPE_MCIPHER, slot_num);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_drv_ks_destory, ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 kapi_symc_create(hi_u32 *id, hi_cipher_type type)
{
    hi_s32 ret;
    hi_u32 chn = 0;
    kapi_symc_ctx *ctx = HI_NULL;

    hi_log_func_enter();

    hi_log_check_param(id == HI_NULL);

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* allocate a aes soft channel for hard channel allocted */
    ret = cryp_symc_alloc_chn(&chn, type);
    if (ret != HI_SUCCESS) {
        for (chn = 1; chn < CRYPTO_HARD_CHANNEL_MAX; chn++) {
            if (((0x1 << chn) & CIPHER_HARD_CHANNEL_MASK) == 0x00) {
                continue;
            }
            hi_log_error("symc channel %d used by PID 0x%x\n", chn, g_kapi_ctx[chn].owner);
        }

        hi_log_error("error, allocate symc channel failed\n");
        hi_log_print_func_err(cryp_symc_alloc_chn, ret);
        kapi_symc_unlock();
        return ret;
    }
    ctx = &g_kapi_ctx[chn];

    ret = memset_s(ctx, sizeof(kapi_symc_ctx), 0, sizeof(kapi_symc_ctx));
    if (ret != HI_SUCCESS) {
        cryp_symc_free_chn(chn);
        hi_log_print_func_err(memset_s, ret);
        kapi_symc_unlock();
        return ret;
    }
    crypto_get_owner(&ctx->owner);

    ret = kapi_symc_alloc_keyslot(&ctx->key_slot);
    if (ret != HI_SUCCESS) {
        cryp_symc_free_chn(chn);
        hi_log_print_func_err(kapi_symc_alloc_keyslot, ret);
        kapi_symc_unlock();
        return ret;
    }

    *id = HI_HANDLE_MAKEHANDLE(HI_ID_CIPHER, 0, chn);
    ctx->open = HI_TRUE;
    ctx->config = HI_FALSE;

    hi_log_info("[SYMC] create handle 0x%x, owner 0x%x, keyslot 0x%x\n", *id, ctx->owner, ctx->key_slot);

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_destroy(hi_u32 id)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];

    check_owner(&ctx->owner);

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    cryp_symc_free_chn(soft_id);

    /* Destroy the attached instance of Symmetric cipher engine */
    if ((ctx->func != HI_NULL) && (ctx->func->destroy != HI_NULL)) {
        ret = ctx->func->destroy((const void *)ctx->cryp_ctx);
        if (ret != HI_SUCCESS) {
            hi_log_error("error, cryp_symc_destory failed\n");
            kapi_symc_unlock();
            return ret;
        }
        ctx->cryp_ctx = HI_NULL;
    }

    ret = kapi_symc_free_keyslot(ctx->key_slot);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(kapi_symc_free_keyslot, ret);
        kapi_symc_unlock();
        return ret;
    }

    ctx->open = HI_FALSE;

    hi_log_info("[SYMC] destroy handle 0x%x, owner 0x%x, keyslot 0x%x\n", id, ctx->owner, ctx->key_slot);

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_get_keyslot(hi_handle cipher,  hi_handle *keyslot)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    hi_log_check_param(keyslot == HI_NULL);
    ret = kapi_symc_check_handle(cipher);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(cipher);
    ctx = &g_kapi_ctx[soft_id];

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    *keyslot = ctx->key_slot;

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}

static hi_s32 kapi_symc_width_check(hi_cipher_alg alg, hi_cipher_work_mode mode, hi_u32 width)
{
    hi_log_func_enter();

    /* the bit width depend on alg and mode, which limit to hardware
     * des/3des with cfb/ofb support bit1, bit8, bit 64.
     * aes with cfb/ofb only support bit128.
     * sm1 with ofb only support bit128, cfb support bit1, bit8, bit 64.
     */
    if (alg == HI_CIPHER_ALG_3DES) {
        if (mode > HI_CIPHER_WORK_MODE_OFB) {
            hi_log_error("Invalid alg %d and mode %d\n", alg, mode);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }

        if ((mode == HI_CIPHER_WORK_MODE_CFB) || (mode == HI_CIPHER_WORK_MODE_OFB)) {
            if ((width != SYMC_DAT_WIDTH_64)
                && (width != SYMC_DAT_WIDTH_8)
                && (width != SYMC_DAT_WIDTH_1)) {
                hi_log_error("Invalid mode %d and bit width %d\n", mode, width);
                hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
                return HI_ERR_CIPHER_INVALID_PARA;
            }
        }
    }

    if (alg == HI_CIPHER_ALG_AES) {
        if (mode > HI_CIPHER_WORK_MODE_MAX) {
            hi_log_error("Invalid alg %d and mode %d\n", alg, mode);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }

        if ((mode == HI_CIPHER_WORK_MODE_CFB)
            && (width != SYMC_DAT_WIDTH_1)
            && (width != SYMC_DAT_WIDTH_8)
            && (width != SYMC_DAT_WIDTH_128)) {
            hi_log_error("Invalid alg %d mode %d and width %d\n", alg, mode, width);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }

        if ((mode == HI_CIPHER_WORK_MODE_OFB)
            && (width != SYMC_DAT_WIDTH_128)) {
            hi_log_error("Invalid alg %d mode %d and width %d\n", alg, mode, width);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }
    }

#ifdef HI_PRODUCT_SM1_SM4_SUPPORT
    if ((alg == HI_CIPHER_ALG_SM4)
        && (mode != HI_CIPHER_WORK_MODE_ECB)
        && (mode != HI_CIPHER_WORK_MODE_CBC)
        && (mode != HI_CIPHER_WORK_MODE_CTR)) {
        hi_log_error("Invalid alg %d and mode %d\n", alg, mode);
        hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
        return HI_ERR_CIPHER_INVALID_PARA;
    }
#endif

    if (alg >= HI_CIPHER_ALG_MAX) {
        hi_log_error("Invalid alg %d .\n", alg);
        hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
        return HI_ERR_CIPHER_INVALID_PARA;
    }

    if (width >= SYMC_DAT_WIDTH_COUNT) {
        hi_log_error("Invalid mode %d\n", width);
        hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
        return HI_ERR_CIPHER_INVALID_PARA;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

static hi_s32 kapi_symc_match_width(hi_cipher_work_mode work_mode,
                                    hi_cipher_bit_width bit_width,
                                    symc_width *width)
{
    hi_log_func_enter();

    /* set the bit width which depend on alg and mode */
    if ((work_mode == HI_CIPHER_WORK_MODE_CFB)
        || (work_mode == HI_CIPHER_WORK_MODE_OFB)) {
        switch (bit_width) {
            case HI_CIPHER_BIT_WIDTH_64BIT: {
                *width = SYMC_DAT_WIDTH_64;
                break;
            }
            case HI_CIPHER_BIT_WIDTH_8BIT: {
                *width = SYMC_DAT_WIDTH_8;
                break;
            }
            case HI_CIPHER_BIT_WIDTH_1BIT: {
                *width = SYMC_DAT_WIDTH_1;
                break;
            }
            case HI_CIPHER_BIT_WIDTH_128BIT: {
                *width = SYMC_DAT_WIDTH_128;
                break;
            }
            default: {
                hi_log_error("Invalid width: 0x%x, mode 0x%x\n",
                             bit_width, work_mode);
                hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
                return HI_ERR_CIPHER_INVALID_PARA;
            }
        }
    } else {
        *width = SYMC_DAT_WIDTH_128;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

static hi_s32 kapi_symc_check_param(hi_u32 iv_usage,
                                    hi_cipher_alg alg,
                                    hi_cipher_work_mode work_mode,
                                    hi_cipher_bit_width bit_width,
                                    symc_width *width)
{
    hi_s32 ret;

    hi_log_func_enter();

    /* set the bit width which depend on alg and mode */
    ret = kapi_symc_match_width(work_mode, bit_width, width);
    if (ret != HI_SUCCESS) {
        hi_log_print_u32(work_mode);
        hi_log_print_u32(bit_width);
        hi_log_print_u32(*width);
        hi_log_print_func_err(kapi_symc_match_width, ret);
        return ret;
    }

    ret = kapi_symc_width_check(alg, work_mode, *width);
    if (ret != HI_SUCCESS) {
        hi_log_print_u32(alg);
        hi_log_print_u32(work_mode);
        hi_log_print_u32(*width);
        hi_log_print_func_err(kapi_symc_width_check, ret);
        return ret;
    }

    if (iv_usage > CIPHER_IV_CHANGE_ONE_PKG_IV_ONLY) {
        hi_log_error("Invalid IV Change Flags: 0x%x\n", iv_usage);
        return HI_ERR_CIPHER_INVALID_PARA;
    }

#ifdef HI_PRODUCT_AEAD_SUPPORT
    if ((iv_usage == CIPHER_IV_CHANGE_ALL_PKG)
        && ((work_mode == HI_CIPHER_WORK_MODE_CCM)
                  || (work_mode == HI_CIPHER_WORK_MODE_GCM))) {
        hi_log_error("Invalid IV Change Flags: 0x%x\n", iv_usage);
        return HI_ERR_CIPHER_INVALID_PARA;
    }
#endif

    hi_log_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_AEAD_SUPPORT
static hi_s32 kapi_symc_check_ccm_gcm_taglen(hi_cipher_alg alg, hi_cipher_work_mode work_mode, hi_u32 tlen)
{
    hi_log_check_param(alg != HI_CIPHER_ALG_AES);

    if (work_mode == HI_CIPHER_WORK_MODE_CCM) {
        /* the parameter t denotes the octet length of T(tag)
         * t is an element of  { 4, 6, 8, 10, 12, 14, 16}
         * here t is pConfig->hi_u32TagLen
 */
        if ((tlen & 0x01)
            || (tlen < AES_CCM_MIN_TAG_LEN)
            || (tlen > AES_CCM_MAX_TAG_LEN)) {
            hi_log_error("Invalid ccm tag len, tlen = 0x%x.\n", tlen);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }
    } else if (work_mode == HI_CIPHER_WORK_MODE_GCM) {
        if ((tlen < AES_GCM_MIN_TAG_LEN) || (tlen > AES_GCM_MAX_TAG_LEN)) {
            hi_log_error("Invalid gcm tag len, tlen = 0x%x.\n", tlen);
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }
    } else {
        hi_log_error("Aes with invalid work mode 0x%x for check tag lenth.\n", work_mode);
        hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
        return HI_ERR_CIPHER_INVALID_PARA;
    }

    return HI_SUCCESS;
}
#endif

static hi_s32 kapi_symc_set_key_iv(hi_u32 id, kapi_symc_ctx *ctx, hi_u32 *klen,
                                   hi_u32 iv_usage, hi_u8 *iv, hi_u32 ivlen)
{
    hi_s32 ret;

    hi_log_func_enter();

    /* Set even key, may be also need set odd key */
    switch (iv_usage) {
        case CIPHER_IV_CHANGE_KEY_ONLY: {
             /* only set key, don't update iv */
            if (ctx->func->setkey != HI_NULL) {
                check_exit(ctx->func->setkey(ctx->cryp_ctx, klen));
                cryp_symc_set_key_source(ctx->cryp_ctx, ctx->key_slot);
            }
            break;
        }
        case CIPHER_IV_CHANGE_ONE_PKG:
        case CIPHER_IV_CHANGE_ALL_PKG: {
            if (ctx->func->setiv != HI_NULL) {
                check_exit(ctx->func->setiv(ctx->cryp_ctx, iv, ivlen, iv_usage));
            }
            if (ctx->func->setkey != HI_NULL) {
                check_exit(ctx->func->setkey(ctx->cryp_ctx, klen));
                cryp_symc_set_key_source(ctx->cryp_ctx, ctx->key_slot);
            }
            break;
        }
        case CIPHER_IV_CHANGE_ONE_PKG_IV_ONLY: {
            /* only set key, don't update iv */
            if (ctx->func->setiv) {
                check_exit(ctx->func->setiv(ctx->cryp_ctx, iv, ivlen, CIPHER_IV_CHANGE_ONE_PKG));
            }
            break;
        }
        default: {
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
        }
    }

    hi_log_func_exit();

    return HI_SUCCESS;

exit__:

    return ret;
}

hi_s32 kapi_symc_config(hi_u32 id,
                        hi_cipher_alg alg,
                        hi_cipher_work_mode work_mode,
                        hi_cipher_bit_width bit_width,
                        hi_cipher_key_length key_len,
                        hi_u8 *iv, hi_u32 ivlen, hi_u32 iv_usage,
                        compat_addr aad, hi_u32 alen, hi_u32 tlen)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    symc_width width = SYMC_DAT_WIDTH_COUNT;
    hi_u32 soft_id;
    hi_u32 klen = key_len;

    hi_log_func_enter();

    hi_log_check_param(alen > MAX_AEAD_A_LEN);
    hi_log_check_param(ADDR_L32(aad) + alen < alen);

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */

    ret = kapi_symc_check_param(iv_usage, alg, work_mode, bit_width, &width);
    if (ret != HI_SUCCESS) {
        hi_log_error("alg 0x%x, work_mode 0x%x\n", alg, work_mode);
        hi_log_print_func_err(kapi_symc_check_param, ret);
        return ret;
    }

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* Destroy the last attached instance of Symmetric cipher engine */
    if ((ctx->func != HI_NULL) && (ctx->func->destroy != HI_NULL)) {
        (void)ctx->func->destroy((const void *)ctx->cryp_ctx);
        ctx->cryp_ctx = HI_NULL;
    }

    /* Clone the function from template of symc engine */
    ctx->func = cryp_get_symc_op(alg, work_mode);
    if (ctx->func == HI_NULL) {
        hi_log_error("error, nonsupport alg %d, work_mode %d\n",
                     alg, work_mode);
        hi_log_print_func_err(cryp_get_symc_op, ret);
        kapi_symc_unlock();
        return HI_ERR_CIPHER_INVALID_PARA;
    }

    /* null means can ignore the function */
    if ((ctx->cryp_ctx == HI_NULL) && (ctx->func->create != HI_NULL)) {
        /* Create a instance from template of engine */
        ctx->cryp_ctx = ctx->func->create(soft_id);
        if (ctx->cryp_ctx == HI_NULL) {
            kapi_symc_unlock();
            return HI_ERR_CIPHER_INVALID_PARA;
        }
    }

    /* set mode and alg */
    if (ctx->func->setmode) {
        ctx->func->setmode(ctx->cryp_ctx, ctx->func->alg, ctx->func->mode, width);
    }

    check_exit(kapi_symc_set_key_iv(id, ctx, &klen, iv_usage, iv, ivlen));

    /* Set AAD */
#ifdef HI_PRODUCT_AEAD_SUPPORT
    if (ctx->func->setadd) {
        hi_log_debug("set add, phy 0x%x, alen %d, tlen %d\n", ADDR_L32(aad), alen, tlen);
        check_exit(kapi_symc_check_ccm_gcm_taglen(alg, work_mode, tlen));
        check_exit(ctx->func->setadd(ctx->cryp_ctx, aad, alen, tlen));
    }
#endif

    /* save crtl */
    check_exit(memset_s(&ctx->ctrl, sizeof(hi_cipher_ctrl), 0, sizeof(hi_cipher_ctrl)));
    ctx->ctrl.alg = alg;
    ctx->ctrl.bit_width = bit_width;
    ctx->ctrl.key_len = key_len;
    ctx->ctrl.work_mode = work_mode;
    ctx->ctrl.change_flags.bit1_iv = iv_usage;

    if (iv != HI_NULL) {
        if (ivlen > AES_IV_SIZE) {
            hi_log_error("error, invalid iv len(0x%x).\n", ivlen);
            kapi_symc_unlock();
            return HI_ERR_CIPHER_INVALID_PARA;
        }
        check_exit(memcpy_s(ctx->ctrl.iv, AES_IV_SIZE, iv, ivlen));
    }

    ctx->config = HI_TRUE;

exit__:
    kapi_symc_unlock();

    hi_log_func_exit();

    return ret;
}

hi_s32 kapi_symc_unlock_get_config(hi_u32 id, hi_cipher_ctrl *ctrl)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    hi_log_check_param(ctrl == HI_NULL);

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */
    hi_log_check_param(ctx->config != HI_TRUE);

    ret = memcpy_s(ctrl, sizeof(hi_cipher_ctrl), &ctx->ctrl, sizeof(hi_cipher_ctrl));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, ret);
        return ret;
    }

    hi_log_func_exit();

    return HI_SUCCESS;
}

hi_s32 kapi_symc_get_config(hi_u32 id, hi_cipher_ctrl *ctrl)
{
    hi_s32 ret;

    hi_log_func_enter();

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = kapi_symc_unlock_get_config(id, ctrl);

    kapi_symc_unlock();

    hi_log_func_exit();

    return ret;
}

hi_s32 kapi_symc_crypto(hi_u32 id, compat_addr input,
                        compat_addr output, hi_u32 length,
                        hi_u32 operation, hi_u32 oddkey,
                        hi_cipher_data_dir data_dir)
{
    hi_s32 ret;
    symc_node_usage usage;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */
    hi_log_check_param(ADDR_U64(input) + length < length);
    hi_log_check_param(ADDR_U64(output) + length < length);
    hi_log_check_param(ctx->func == HI_NULL);
    hi_log_check_param(ctx->func->crypto == HI_NULL);
    hi_log_check_param(ctx->config != HI_TRUE);
    hi_log_check_param((operation != 0x00) && (operation != 0x01));

    usage = SYMC_NODE_USAGE_NORMAL;

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    cryp_symc_set_data_dir(ctx->cryp_ctx, data_dir);

    ret = ctx->func->crypto(ctx->cryp_ctx, operation, &input,
                            &output, &length, &usage, 1, HI_TRUE);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(ctx->func->crypto, ret);
        kapi_symc_unlock();
        return ret;
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_MULTI_CIPHER_SUPPORT
static hi_s32 kapi_symc_crypto_multi_start(kapi_symc_ctx *ctx, const void *pkg, hi_u32 pkg_num, hi_u32 operation,
                                           hi_u32 wait, hi_cipher_data_dir data_dir)
{
    hi_s32 ret;
    void *buf = HI_NULL;
    void *temp = HI_NULL;
    compat_addr *input = HI_NULL;
    compat_addr *output = HI_NULL;
    symc_node_usage *usage = HI_NULL;
    hi_u64 input_phy;
    hi_u64 output_phy;
    hi_bool in_is_sec;
    hi_bool out_is_sec;
    hi_cipher_data pkg_tmp;
    hi_u32 *length = HI_NULL;
    hi_u32 size;
    hi_u32 i;

    hi_log_func_enter();

    hi_log_check_param(ctx->func == HI_NULL);
    hi_log_check_param(ctx->func->crypto == HI_NULL);
    hi_log_check_param(pkg == HI_NULL);
    hi_log_check_param(pkg_num > MAX_PKG_NUMBER);
    hi_log_check_param(pkg_num == 0x00);

    /* size of input:output:usage:length */
    size = (sizeof(compat_addr) + sizeof(compat_addr) + sizeof(hi_u32) + sizeof(hi_u32)) * pkg_num;

    buf = crypto_malloc(size);
    if (buf == HI_NULL) {
        hi_log_error("Malloc for pkg failed.\n");
        return HI_ERR_CIPHER_FAILED_MEM;
    }

    temp = buf;
    input = (compat_addr *)temp;
    temp = (hi_u8 *)temp + sizeof(compat_addr) * pkg_num; /* buf + input */
    output = (compat_addr *)temp;
    temp = (hi_u8 *)temp + sizeof(compat_addr) * pkg_num; /* buf + input + output */
    usage = temp;
    temp = (hi_u8 *)temp + sizeof(hi_u32) * pkg_num; /* buf + input + output + usage */
    length = temp;

    ret = crypto_judge_sec_mem(data_dir, &in_is_sec, &out_is_sec);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(crypto_judge_sec_mem, ret);
        return ret;
    }
    /* Compute and check the nodes length */
    for (i = 0; i < pkg_num; i++) {
        /* copy node list from user space to kernel */
        ret = crypto_copy_from_user(&pkg_tmp, sizeof(hi_cipher_data),
                                    (hi_u8 *)pkg + sizeof(hi_cipher_data) * i, sizeof(hi_cipher_data));
        if (ret != HI_SUCCESS) {
            hi_log_error("copy data from user fail!\n");
            hi_log_print_func_err(crypto_copy_from_user, ret);
            crypto_free(buf);
            buf = HI_NULL;
            return ret;
        }

        ret = crypto_bufhandle_to_phys(&input_phy, pkg_tmp.src_phy_addr, in_is_sec);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(crypto_bufhandle_to_phys, ret);
            crypto_free(buf);
            buf = HI_NULL;
            return ret;
        }
        ret = crypto_bufhandle_to_phys(&output_phy, pkg_tmp.dest_phy_addr, out_is_sec);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(crypto_bufhandle_to_phys, ret);
            crypto_free(buf);
            buf = HI_NULL;
            return ret;
        }

        ADDR_U64(input[i]) = input_phy;
        ADDR_U64(output[i]) = output_phy;
        if (ADDR_U64(input[i]) + pkg_tmp.byte_length < pkg_tmp.byte_length) {
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            crypto_free(buf);
            buf = HI_NULL;
            return HI_ERR_CIPHER_INVALID_PARA;
        }

        if (ADDR_U64(output[i]) + pkg_tmp.byte_length < pkg_tmp.byte_length) {
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            crypto_free(buf);
            buf = HI_NULL;
            return HI_ERR_CIPHER_INVALID_PARA;
        }

        length[i] = pkg_tmp.byte_length;

#ifdef HI_PRODUCT_ODD_KEY_SUPPORT
#ifdef CHIP_SYMC_ODD_KEY_SUPPORT
        usage[i] = pkg_tmp.odd_key ? SYMC_NODE_USAGE_ODD_KEY : SYMC_NODE_USAGE_EVEN_KEY;
#else
        if (pkg_tmp.odd_key == HI_TRUE) {
            hi_log_error("symc nonsupport odd key!\n");
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            crypto_free(buf);
            buf = HI_NULL;
            return HI_ERR_CIPHER_INVALID_PARA;
        }
        usage[i] = SYMC_NODE_USAGE_EVEN_KEY;
#endif
#endif
        hi_log_debug("pkg %d, in 0x%x, out 0x%x, length 0x%x, usage 0x%x\n", i,
                     ADDR_L32(input[i]), ADDR_L32(output[i]), length[i], usage[i]);
    }

    ret = ctx->func->crypto(ctx->cryp_ctx, operation, input,
                            output, length, usage, pkg_num, wait);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(cryp_symc_crypto, ret);
        crypto_free(buf);
        buf = HI_NULL;
        return ret;
    }

    crypto_free(buf);
    buf = HI_NULL;

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_crypto_multi(hi_u32 id, const hi_void *pkg, hi_u32 pkg_num,
                              hi_u32 operation, hi_cipher_data_dir data_dir)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */
    hi_log_check_param(ctx->func == HI_NULL);
    hi_log_check_param(ctx->config != HI_TRUE);
    hi_log_check_param((operation != 0x00) && (operation != 0x01));

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    cryp_symc_set_data_dir(ctx->cryp_ctx, data_dir);

    ret = kapi_symc_crypto_multi_start(ctx, pkg, pkg_num, operation, HI_TRUE, data_dir);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(kapi_symc_crypto_multi_start, ret);
        kapi_symc_unlock();
        return ret;
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}
#endif

#ifdef HI_PRODUCT_AEAD_SUPPORT
hi_s32 kapi_aead_get_tag(hi_u32 id, hi_u32 tag[AEAD_TAG_SIZE_IN_WORD], hi_u32 *taglen)
{
    hi_s32 ret;
    kapi_symc_ctx *ctx = HI_NULL;
    hi_u32 soft_id;

    hi_log_func_enter();

    hi_log_check_param(tag == HI_NULL);
    hi_log_check_param(taglen == HI_NULL);
    hi_log_check_param(*taglen != AES_CCM_MAX_TAG_LEN);

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */
    hi_log_check_param(ctx->func == HI_NULL);

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (ctx->func->gettag) {
        ret = ctx->func->gettag(ctx->cryp_ctx, tag, taglen);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(cryp_aead_get_tag, ret);
            kapi_symc_unlock();
            return ret;
        }
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}
#endif

/* This function will be called by KLAD */
#ifdef HI_PRODUCT_CBC_MAC_SUPPORT
hi_s32 kapi_symc_setiv(hi_u32 id, hi_u8 *iv, hi_u32 ivlen)
{
    hi_s32 ret;
    hi_u32 soft_id;
    kapi_symc_ctx *ctx = HI_NULL;

    hi_log_func_enter();

    hi_log_check_param(iv == HI_NULL);
    hi_log_check_param(ivlen > AES_IV_SIZE);

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if ((ctx->func != HI_NULL) && (ctx->func->setiv != HI_NULL)) {
        ret = ctx->func->setiv(ctx->cryp_ctx, iv, ivlen, CIPHER_IV_CHANGE_ONE_PKG);
        if (ret != HI_SUCCESS) {
            hi_log_print_h32(ivlen);
            kapi_symc_unlock();
            return ret;
        }
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 kapi_symc_getiv(hi_u32 id, hi_u8 *iv, hi_u32 iv_buf_len, hi_u32 *ivlen)
{
    hi_s32 ret;
    hi_u32 soft_id;
    kapi_symc_ctx *ctx = HI_NULL;

    hi_log_func_enter();

    hi_log_check_param(iv == HI_NULL);
    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */
    hi_log_check_param(ctx->func == HI_NULL);
    hi_log_check_param(ctx->func->getiv == HI_NULL);

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = ctx->func->getiv(ctx->cryp_ctx, iv, iv_buf_len, ivlen);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(cryp_symc_getiv, ret);
        return ret;
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}
#endif

#if defined(HI_PRODUCT_CENC_SUPPORT)
hi_s32 kapi_symc_cenc_decrypt(hi_u32 id,
                              hi_cipher_cenc *cenc,
                              compat_addr inputphy,
                              compat_addr outputphy,
                              hi_u32 bytelength)
{
    hi_s32 ret;
    hi_u32 soft_id;
    kapi_symc_ctx *ctx = HI_NULL;

    hi_log_func_enter();

    ret = kapi_symc_check_handle(id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    ctx = &g_kapi_ctx[soft_id];
    check_owner(&ctx->owner); /* called by user space, must check the pid */

    ret = kapi_symc_lock();
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = cenc_decrypt(id, cenc, inputphy, outputphy, bytelength);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(cenc_decrypt, ret);
        kapi_symc_unlock();
        return ret;
    }

    kapi_symc_unlock();

    hi_log_func_exit();
    return HI_SUCCESS;
}
#endif

hi_s32 kapi_symc_get_user_uuid(hi_u32 id, TEE_UUID *pstUUID)
{
    hi_s32 ret;
    hi_u32 soft_id;
    kapi_symc_ctx *ctx = HI_NULL;

    hi_log_func_enter();

    hi_log_check_param(pstUUID == HI_NULL);

    if ((HI_ID_CIPHER != HI_HANDLE_GET_MODID(id)) || (0 != HI_HANDLE_GET_PriDATA(id))) {
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }

    soft_id = HI_HANDLE_GET_CHNID(id);
    if (soft_id >= CRYPTO_HARD_CHANNEL_MAX) {
        hi_log_error("chan %d is too large, max: %d\n", soft_id, CRYPTO_HARD_CHANNEL_MAX);
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }
    ctx = &g_kapi_ctx[soft_id];

    if (ctx->open == HI_FALSE) {
        hi_log_error("chan %d is non_secure channel!\n", soft_id);
        return HI_ERR_CIPHER_INVALID_HANDLE;
    }

    ret = memcpy_s(pstUUID, sizeof(crypto_owner), &ctx->owner, sizeof(crypto_owner));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, ret);
        return ret;
    }

    hi_log_print_h32(sizeof(crypto_owner));

    hi_log_func_exit();
    return HI_SUCCESS;
}
