/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee mpi cipher
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "user_osal_lib.h"
#include "sys_cipher.h"
#include "posix_types.h"

crypto_mutex g_cipher_mutex = PTHREAD_MUTEX_INITIALIZER;

#define hi_cipher_lock()   (void)crypto_mutex_lock(&g_cipher_mutex)
#define hi_cipher_unlock() (void)crypto_mutex_unlock(&g_cipher_mutex)

#define BYTE_BITS               8
#define CIPHER_MAX_MULTIPAD_NUM 5000
#define CENC_SUBSAMPLE_MAX_NUM  100
#define ECDH_MAX_KEY_LEN        72
#define CIPHER_INIT_MAX_NUM     0x7FFFFFFF
#define TRNG_TIMEOUT            10000

/* handle of cipher device */
hi_s32 g_cipher_dev_fd = -1;

/* flag of cipher device
 * indicate the status of device that open or close
 * <0: close, 0: open>0: multiple initialization
 */
static hi_s32 g_cipher_init_counter = -1;

/* check the device of cipher whether already opend or not */
#define check_cipher_open()                                    \
    do {                                                       \
        if (g_cipher_init_counter < 0) {                         \
            hi_log_err("cipher init counter %d\n", g_cipher_init_counter); \
            hi_err_print_err_code(HI_ERR_CIPHER_NOT_INIT);       \
            return HI_ERR_CIPHER_NOT_INIT;                     \
        }                                                      \
    } while (0)


/**
 * Read E in public key from arry to U32,
 * so only use last byte0~byte3, others are zero
 */
#define cipher_get_pub_exponent(_e, _rsades)                 \
    do {                                                        \
        hi_u8 *_buf = (_rsades)->pub_key.e;                  \
        hi_u8 *_pub = (hi_u8 *)(_e);                         \
        hi_u32 _len = (_rsades)->pub_key.e_len;              \
        hi_u32 _i;                                           \
        for (_i = 0; _i < MIN(WORD_WIDTH, _len); _i++) {     \
            _pub[WORD_WIDTH - _i - 1] = _buf[_len - _i - 1]; \
        }                                                    \
    } while (0)

#define CENC_MSG_CMD_EXIT        0x55
#define CENC_MSG_CMD_DEC         0xaa

typedef struct {
    hi_u32 cmd;
    hi_handle cipher;
    hi_cipher_cenc cenc;
    hi_mem_handle input;
    hi_mem_handle output;
    hi_u32 length;
    hi_cipher_cb_done_notify symc_done;
}mpi_cenc_dec_msg;

#ifdef HI_PRODUCT_CENC_SUPPORT

static queue_pool g_cenc_dec_queue;
static pthread_t  g_cenc_dec_thread   = 0;
static hi_u32  g_cenc_thread_workking = HI_FALSE;

static hi_void *cenc_dec_func(hi_void *arg)
{
    hi_s32 ret;
    mpi_cenc_dec_msg msg;

    hi_dbg_func_enter();

    while (g_cenc_thread_workking == HI_TRUE) {
        ret = queue_pool_read(&g_cenc_dec_queue, &msg, sizeof(msg));
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(queue_pool_read, ret);
            return HI_NULL;
        }

        if (msg.cmd == CENC_MSG_CMD_EXIT) {
            hi_dbg_func_exit();
            return HI_NULL;
        }

        if (msg.symc_done.symc_done == HI_NULL) {
            hi_log_warn("invalid message callback function\n");
            continue;
        }

        ret = hi_mpi_cipher_cenc_decrypt(msg.cipher, &msg.cenc, msg.input, msg.output, msg.length);

        /* callback notify user */
        msg.symc_done.symc_done(msg.cipher, ret, msg.symc_done.user_data, msg.symc_done.data_size);
    }

    hi_dbg_func_exit();
    return HI_NULL;
}

static hi_s32 hi_mpi_cipher_asyn_init(hi_void)
{
    hi_s32 ret;
    pthread_attr_t thread_attr;

    hi_dbg_func_enter();

    ret = queue_pool_create(&g_cenc_dec_queue, sizeof(mpi_cenc_dec_msg), QUEUE_POOL_MAX_DEPTH);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(queue_pool_create, ret);
        return ret;
    }

    g_cenc_thread_workking = HI_TRUE;

    pthread_attr_init(&thread_attr);
    pthread_attr_settee(&thread_attr, TEESMP_THREAD_ATTR_CA_INHERIT,
        TEESMP_THREAD_ATTR_TASK_ID_INHERIT, TEESMP_THREAD_ATTR_NO_SHADOW);
    ret = pthread_create(&g_cenc_dec_thread, &thread_attr, cenc_dec_func, HI_NULL);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_create, ret);
        (hi_void)queue_pool_destroy(&g_cenc_dec_queue);
        g_cenc_thread_workking = HI_FALSE;
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

static hi_s32 hi_mpi_cipher_asyn_deinit(hi_void)
{
    hi_s32 ret;
    mpi_cenc_dec_msg msg;

    hi_dbg_func_enter();

    ret = memset_s(&msg, sizeof(msg), 0, sizeof(mpi_cenc_dec_msg));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    msg.cmd  = CENC_MSG_CMD_EXIT;
    ret = queue_pool_write(&g_cenc_dec_queue, &msg, sizeof(msg));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(queue_pool_write, ret);
        return ret;
    }
    g_cenc_thread_workking = HI_FALSE;
    pthread_join(g_cenc_dec_thread, HI_NULL);

    ret = queue_pool_destroy(&g_cenc_dec_queue);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(queue_pool_destroy, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

/**
 * \brief  Init the cipher device.
 */
hi_s32 hi_mpi_cipher_init(hi_void)
{
#ifdef HI_PRODUCT_CENC_SUPPORT
    hi_s32 ret;
#endif

    hi_dbg_func_enter();

    hi_cipher_lock();

    if (g_cipher_init_counter >= CIPHER_INIT_MAX_NUM) {
        hi_cipher_unlock();

        hi_err_print_err_code(HI_ERR_CIPHER_OVERFLOW);
        return HI_ERR_CIPHER_OVERFLOW;
    }

    if (g_cipher_init_counter >= 0) {
        g_cipher_init_counter++;
        hi_cipher_unlock();

        hi_dbg_func_exit();
        return HI_SUCCESS;
    }

    g_cipher_dev_fd = crypto_open("cipher", O_RDWR, 0);
    if (g_cipher_dev_fd < 0) {
        hi_cipher_unlock();

        hi_err_print_call_fun_err(crypto_open, HI_ERR_CIPHER_FAILED_INIT);
        return HI_ERR_CIPHER_FAILED_INIT;
    }

#ifdef HI_PRODUCT_CENC_SUPPORT
    ret = hi_mpi_cipher_asyn_init();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_asyn_init, ret);
        (hi_void)crypto_close(g_cipher_dev_fd);
        g_cipher_dev_fd = -1;
        hi_cipher_unlock();
        return ret;
    }
#endif

    g_cipher_init_counter = 0;

    hi_cipher_unlock();

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief  Deinit the cipher device.
 */
hi_s32 hi_mpi_cipher_deinit(hi_void)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    hi_cipher_lock();

    if (g_cipher_init_counter < 0) {
        hi_cipher_unlock();

        hi_dbg_func_exit();
        return HI_SUCCESS;
    }

    if (g_cipher_init_counter > 0) {
        g_cipher_init_counter--;

        hi_cipher_unlock();

        hi_dbg_func_exit();
        return HI_SUCCESS;
    }

#ifdef HI_PRODUCT_CENC_SUPPORT
    ret = hi_mpi_cipher_asyn_deinit();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_asyn_deinit, ret);
        hi_cipher_unlock();
        return ret;
    }
#endif

    ret = crypto_close(g_cipher_dev_fd);
    if (ret != HI_SUCCESS) {
        hi_cipher_unlock();

        hi_err_print_call_fun_err(crypto_close, ret);
        return ret;
    }

    g_cipher_dev_fd = -1;
    g_cipher_init_counter = -1;

    hi_cipher_unlock();

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief Obtain a cipher handle for encryption and decryption.
 */
hi_s32 hi_mpi_cipher_create_handle(hi_handle *handle, const hi_cipher_attr *cipher_attr)
{
    hi_s32 ret;
    hi_u32 id = 0;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(handle == HI_NULL);
    HI_LOG_CHECK_PARAM(cipher_attr == HI_NULL);
    HI_LOG_CHECK_PARAM(cipher_attr->cipher_type >= HI_CIPHER_TYPE_MAX);

    hi_dbg_print_u32(cipher_attr->cipher_type);

    check_cipher_open();

    ret = sys_symc_create(&id, cipher_attr->cipher_type);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_create, ret);
        return ret;
    }

    *handle = id;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_RSA_SUPPORT
static hi_s32 cipher_get_rsa_attr(hi_u32 scheme, hi_u32 *h_len,
                                  hi_cipher_hash_type *sha_type)
{
    hi_dbg_func_enter();

    switch (scheme) {
        case HI_CIPHER_RSA_ENC_SCHEME_NO_PADDING:
        case HI_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_0:
        case HI_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_1:
        case HI_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_2:
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_PKCS1_V1_5: {
            *h_len = 0;
            *sha_type = HI_CIPHER_HASH_TYPE_MAX;

            break;
        }
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA1:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA1:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA1: {
            *h_len = SHA1_RESULT_SIZE;
            *sha_type = HI_CIPHER_HASH_TYPE_SHA1;

            break;
        }
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA224:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA224:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA224:
            *h_len = SHA224_RESULT_SIZE;
            *sha_type = HI_CIPHER_HASH_TYPE_SHA224;

            break;
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA256:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA256: {
            *h_len = SHA256_RESULT_SIZE;
            *sha_type = HI_CIPHER_HASH_TYPE_SHA256;
            break;
        }
#ifdef HI_PRODUCT_SHA512_SUPPORT
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA384:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA384:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA384: {
            *h_len = SHA384_RESULT_SIZE;
            *sha_type = HI_CIPHER_HASH_TYPE_SHA384;

            break;
        }
        case HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA512:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA512:
        case HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA512: {
            *h_len = SHA512_RESULT_SIZE;
            *sha_type = HI_CIPHER_HASH_TYPE_SHA512;
            break;
        }
#endif
        default: {
            hi_dbg_print_u32(scheme);
            hi_err_print_err_code(HI_ERR_CIPHER_UNAVAILABLE);
            return HI_ERR_CIPHER_UNAVAILABLE;
        }
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

/**
 * \brief Destroy the existing cipher handle.
 */
hi_s32 hi_mpi_cipher_destroy_handle(hi_handle handle)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    check_cipher_open();

    ret = sys_symc_destroy(handle);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_destroy, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_get_keyslot_handle(hi_handle cipher,  hi_handle *keyslot)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(keyslot == HI_NULL);

    check_cipher_open();

    ret = sys_symc_get_keyslot_handle(cipher, keyslot);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_get_keyslot_handle, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief Configures the cipher control information.
 */
hi_s32 hi_mpi_cipher_config_handle(hi_handle handle, const hi_cipher_ctrl *ctrl)
{
    hi_u32 ivlen = AES_IV_SIZE;
    hi_mem_handle aad;
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(ctrl == HI_NULL);
    HI_LOG_CHECK_PARAM(handle == HI_INVALID_HANDLE);

    check_cipher_open();

    if (ctrl->alg == HI_CIPHER_ALG_3DES) {
        ivlen = DES_IV_SIZE;
    }

    hi_dbg_print_u32(handle);
    hi_dbg_print_u32(ctrl->alg);
    hi_dbg_print_u32(ctrl->work_mode);
    hi_dbg_print_u32(ctrl->bit_width);
    hi_dbg_print_u32(ctrl->key_len);
    hi_dbg_print_u32(ivlen);
    hi_dbg_print_u32(ctrl->change_flags.bit1_iv);

    ret = sys_symc_config(handle, ctrl->alg, ctrl->work_mode,
                          ctrl->bit_width, ctrl->key_len,
                          (hi_u8 *)ctrl->iv, ivlen, ctrl->change_flags.bit1_iv,
                          aad, 0, 0);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_config, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief Configures the cipher expand control information.
 */
hi_s32 hi_mpi_cipher_config_handle_ex(hi_handle handle, const hi_cipher_ctrl_ex *ctrl_ex)
{
#ifdef HI_PRODUCT_SYMC_CONFIG_EX_SUPPORT
    hi_cipher_key_length key_len = HI_CIPHER_KEY_DEFAULT;
    hi_u8 *iv = HI_NULL;
    hi_u32 usage = 0;
    hi_mem_handle aad;
    hi_u32 a_len = 0;
    hi_u32 tag_len = 0;
    hi_u32 iv_len = 0;
    hi_cipher_bit_width bit_width = HI_CIPHER_BIT_WIDTH_128BIT;
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(ctrl_ex == HI_NULL);
    HI_LOG_CHECK_PARAM((ctrl_ex->param == HI_NULL) && (ctrl_ex->alg != HI_CIPHER_ALG_DMA));

    check_cipher_open();

    ret = memset_s(&aad, sizeof(aad), 0, sizeof(hi_mem_handle));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    /*****************************************************************************
     * for AES, the pointer should point to hi_cipher_ctrl_aes;
     * for AES_CCM or AES_GCM, the pointer should point to hi_cipher_ctrl_aes_ccm_gcm;
     * for DES, the pointer should point to hi_cipher_ctrl_des;
     * for 3DES, the pointer should point to hi_cipher_ctrl_3des;
     * for SM1, the pointer should point to hi_cipher_ctrl_sm1;
     * for SM4, the pointer should point to hi_cipher_ctrl_sm4;
     */
    switch (ctrl_ex->alg) {
        case HI_CIPHER_ALG_3DES: {
            hi_cipher_ctrl_3des *tdes_ctrl = (hi_cipher_ctrl_3des *)ctrl_ex->param;
            iv = (hi_u8 *)tdes_ctrl->iv;
            usage = tdes_ctrl->change_flags.bit1_iv;
            key_len = tdes_ctrl->key_len;
            iv_len = DES_IV_SIZE;
            bit_width = tdes_ctrl->bit_width;
            break;
        }
        case HI_CIPHER_ALG_AES: {
            if ((ctrl_ex->work_mode == HI_CIPHER_WORK_MODE_CCM)
                || (ctrl_ex->work_mode == HI_CIPHER_WORK_MODE_GCM)) {
                hi_cipher_ctrl_aes_ccm_gcm *aes_ccm_gcm_ctrl = (hi_cipher_ctrl_aes_ccm_gcm *)ctrl_ex->param;

                iv = (hi_u8 *)aes_ccm_gcm_ctrl->iv;
                iv_len = aes_ccm_gcm_ctrl->iv_len;

                if (iv_len > AES_IV_SIZE) {
                    hi_log_err("para set CIPHER ccm/gcm iv is invalid, iv_len:0x%x.\n", iv_len);
                    hi_err_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
                    return HI_ERR_CIPHER_INVALID_PARA;
                }

                tag_len = aes_ccm_gcm_ctrl->tag_len;
                key_len = aes_ccm_gcm_ctrl->key_len;
                aad.mem_handle = aes_ccm_gcm_ctrl->a_phy_addr.mem_handle;
                aad.addr_offset = aes_ccm_gcm_ctrl->a_phy_addr.addr_offset;
                a_len = aes_ccm_gcm_ctrl->a_len;
                usage = CIPHER_IV_CHANGE_ONE_PKG;
            } else {
                hi_cipher_ctrl_aes *aes_ctrl = (hi_cipher_ctrl_aes *)ctrl_ex->param;
                iv = (hi_u8 *)aes_ctrl->iv;
                usage = aes_ctrl->change_flags.bit1_iv;
                key_len = aes_ctrl->key_len;
                bit_width = aes_ctrl->bit_width;
                iv_len = AES_IV_SIZE;
            }
            break;
        }

        case HI_CIPHER_ALG_SM4: {
            hi_cipher_ctrl_sm4 *sm4_ctrl = (hi_cipher_ctrl_sm4 *)ctrl_ex->param;

            iv = (hi_u8 *)sm4_ctrl->iv;
            usage = sm4_ctrl->change_flags.bit1_iv;
            key_len = HI_CIPHER_KEY_DEFAULT;
            iv_len = AES_IV_SIZE;
            break;
        }
        case HI_CIPHER_ALG_DMA: {
            break;
        }
        default:
            hi_log_err("para set CIPHER alg is invalid.\n");
            hi_err_print_err_code(HI_ERR_CIPHER_INVALID_PARA);
            return HI_ERR_CIPHER_INVALID_PARA;
    }

    ret = sys_symc_config(handle, ctrl_ex->alg,
                          ctrl_ex->work_mode, bit_width, key_len,
                          iv, iv_len,
                          usage, aad, a_len, tag_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_config, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

/**
 * \brief Performs encryption.
 */
hi_s32 hi_mpi_cipher_encrypt(hi_handle handle, hi_mem_handle src_buf, hi_mem_handle dest_buf,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    check_cipher_open();

    hi_dbg_print_u32(handle);
    hi_dbg_print_u32(byte_length);

    ret = sys_symc_crypto(handle, src_buf, dest_buf, byte_length, SYMC_OPERATION_ENCRYPT, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_crypto, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief Performs descryption.
 */
hi_s32 hi_mpi_cipher_decrypt(hi_handle handle, hi_mem_handle src_buf, hi_mem_handle dest_buf,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    hi_dbg_print_u32(handle);
    hi_dbg_print_u32(byte_length);

    check_cipher_open();

    ret = sys_symc_crypto(handle, src_buf, dest_buf, byte_length, SYMC_OPERATION_DECRYPT, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_crypto, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/**
 * \brief Encrypt multiple packaged data.
 */
hi_s32 hi_mpi_cipher_encrypt_multi(hi_handle handle,
                                   const hi_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir)
{
#ifdef HI_PRODUCT_MULTI_CIPHER_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    check_cipher_open();

    HI_LOG_CHECK_PARAM(data_pkg == HI_NULL);
    HI_LOG_CHECK_PARAM(data_pkg_num == 0x00);
    HI_LOG_CHECK_PARAM(data_pkg_num >= CIPHER_MAX_MULTIPAD_NUM);

    hi_dbg_print_u32(handle);
    hi_dbg_print_u32(data_pkg_num);

    ret = sys_symc_crypto_multi(handle, data_pkg, data_pkg_num, SYMC_OPERATION_ENCRYPT, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_crypto_multi, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

/**
 * \brief Decrypt multiple packaged data.
 */
hi_s32 hi_mpi_cipher_decrypt_multi(hi_handle handle,
                                   const hi_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir)
{
#ifdef HI_PRODUCT_MULTI_CIPHER_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(data_pkg == HI_NULL);
    HI_LOG_CHECK_PARAM(data_pkg_num == 0x00);
    HI_LOG_CHECK_PARAM(data_pkg_num >= CIPHER_MAX_MULTIPAD_NUM);

    hi_dbg_print_u32(handle);
    hi_dbg_print_u32(data_pkg_num);

    check_cipher_open();

    ret = sys_symc_crypto_multi(handle, data_pkg, data_pkg_num, SYMC_OPERATION_DECRYPT, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_crypto_multi, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_get_tag(hi_handle handle, hi_u8 *tag, hi_u32 *tag_len)
{
#ifdef HI_PRODUCT_AEAD_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(tag == HI_NULL);
    HI_LOG_CHECK_PARAM(tag_len == HI_NULL);
    HI_LOG_CHECK_PARAM(*tag_len != AEAD_TAG_SIZE);

    hi_dbg_print_u32(handle);

    check_cipher_open();

    ret = sys_aead_get_tag(handle, tag, tag_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_aead_get_tag, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_get_handle_config(hi_handle handle, hi_cipher_ctrl *ctrl)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(ctrl == HI_NULL);

    check_cipher_open();

    ret = sys_symc_get_config(handle, ctrl);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_symc_get_config, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_get_multi_random_bytes(hi_u8 *random_byte, hi_u32 bytes)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(random_byte == HI_NULL);

    ret = sys_trng_get_random(random_byte, bytes, TRNG_TIMEOUT);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_trng_get_random, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_get_random_number(hi_u32 *random_number, hi_u32 time_out_us)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(random_number == HI_NULL);

    ret = sys_trng_get_random((hi_u8 *)random_number, WORD_WIDTH, time_out_us);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_hash_init(const hi_cipher_hash_attr *hash_attr, hi_handle *hash_handle)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(hash_attr == HI_NULL);
    HI_LOG_CHECK_PARAM(hash_handle == HI_NULL);

    if ((hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SHA1) ||
        (hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SHA224) ||
        (hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SHA256) ||
        (hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SHA384) ||
        (hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SHA512) ||
        (hash_attr->hash_type == HI_CIPHER_HASH_TYPE_HMAC_SM3)) {
        HI_LOG_CHECK_PARAM(hash_attr->hmac_key == HI_NULL);
    }

    hi_dbg_print_u32(hash_attr->hash_type);
    hi_dbg_print_u32(hash_attr->hmac_key_len);

    check_cipher_open();

    ret = sys_hash_start(hash_handle,
                         hash_attr->hash_type,
                         hash_attr->hmac_key,
                         hash_attr->hmac_key_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_start, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_hash_update(hi_handle hash_handle, const hi_u8 *input_data, hi_u32 input_data_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(input_data == HI_NULL);

    hi_dbg_print_u32(hash_handle);
    hi_dbg_print_u32(input_data_len);

    check_cipher_open();

    ret = sys_hash_update(hash_handle, input_data, input_data_len, HASH_CHUNCK_SRC_USER);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_update, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cipher_hash_final(hi_handle hash_handle, hi_u8 *output_hash, hi_u32 *hash_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(output_hash == HI_NULL);
    HI_LOG_CHECK_PARAM(hash_handle == HI_INVALID_HANDLE);

    hi_dbg_print_u32(hash_handle);

    check_cipher_open();

    ret = sys_hash_finish(hash_handle, output_hash, hash_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_finish, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

#ifdef HI_PRODUCT_RSA_SUPPORT
static hi_s32 check_rsa_pri_key(hi_cipher_rsa_pri_key *pri_key)
{
    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(pri_key == HI_NULL);
    HI_LOG_CHECK_PARAM(pri_key->n == HI_NULL);
    HI_LOG_CHECK_PARAM(pri_key->n_len < RSA_MIN_KEY_LEN);
    HI_LOG_CHECK_PARAM(pri_key->n_len > RSA_MAX_KEY_LEN);

    if (pri_key->d == HI_NULL) {
        HI_LOG_CHECK_PARAM(pri_key->p == HI_NULL);
        HI_LOG_CHECK_PARAM(pri_key->q == HI_NULL);
        HI_LOG_CHECK_PARAM(pri_key->dp == HI_NULL);
        HI_LOG_CHECK_PARAM(pri_key->dq == HI_NULL);
        HI_LOG_CHECK_PARAM(pri_key->qp == HI_NULL);
        HI_LOG_CHECK_PARAM((pri_key->n_len >> 1) != pri_key->p_len);
        HI_LOG_CHECK_PARAM((pri_key->n_len >> 1) != pri_key->q_len);
        HI_LOG_CHECK_PARAM((pri_key->n_len >> 1) != pri_key->dp_len);
        HI_LOG_CHECK_PARAM((pri_key->n_len >> 1) != pri_key->dq_len);
        HI_LOG_CHECK_PARAM((pri_key->n_len >> 1) != pri_key->qp_len);
    } else {
        HI_LOG_CHECK_PARAM(pri_key->n_len != pri_key->d_len);
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
#endif

hi_s32 hi_mpi_cipher_rsa_public_encrypt(const hi_cipher_rsa_pub_enc *rsa_enc,
                                        const hi_u8 *input, hi_u32 in_len,
                                        hi_u8 *output, hi_u32 *output_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_enc == HI_NULL);
    HI_LOG_CHECK_PARAM(input == HI_NULL);
    HI_LOG_CHECK_PARAM(output == HI_NULL);
    HI_LOG_CHECK_PARAM(output_len == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_enc->pub_key.n == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_enc->pub_key.e == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_enc->pub_key.n_len < RSA_MIN_KEY_LEN);
    HI_LOG_CHECK_PARAM(rsa_enc->pub_key.n_len > RSA_MAX_KEY_LEN);
    HI_LOG_CHECK_PARAM(rsa_enc->pub_key.n_len < rsa_enc->pub_key.e_len);

    hi_dbg_print_u32(rsa_enc->pub_key.n_len);
    hi_dbg_print_u32(rsa_enc->scheme);
    hi_dbg_print_u32(in_len);

    check_cipher_open();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_TRUE;
    key.klen = rsa_enc->pub_key.n_len;
    key.n = rsa_enc->pub_key.n;

    cipher_get_pub_exponent(&key.e, rsa_enc);

    ret = sys_rsa_encrypt(&key, rsa_enc->scheme,
                          input, in_len,
                          output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_rsa_private_decrypt(const hi_cipher_rsa_pri_enc *rsa_dec,
                                         const hi_u8 *input, hi_u32 in_len,
                                         hi_u8 *output, hi_u32 *output_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_dec == HI_NULL);

    ret = check_rsa_pri_key(&((hi_cipher_rsa_pri_enc *)rsa_dec)->pri_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_rsa_pri_key, ret);
        return ret;
    }

    HI_LOG_CHECK_PARAM(input == HI_NULL);
    HI_LOG_CHECK_PARAM(output == HI_NULL);
    HI_LOG_CHECK_PARAM(output_len == HI_NULL);

    hi_dbg_print_u32(rsa_dec->pri_key.n_len);
    hi_dbg_print_u32(rsa_dec->scheme);
    hi_dbg_print_u32(in_len);

    check_cipher_open();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_FALSE;
    key.klen = rsa_dec->pri_key.n_len;
    key.n = rsa_dec->pri_key.n;
    key.d = rsa_dec->pri_key.d;
    key.p = rsa_dec->pri_key.p;
    key.q = rsa_dec->pri_key.q;
    key.dp = rsa_dec->pri_key.dp;
    key.dq = rsa_dec->pri_key.dq;
    key.qp = rsa_dec->pri_key.qp;

    ret = sys_rsa_decrypt(&key,
                          rsa_dec->scheme,
                          input, in_len,
                          output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_rsa_private_encrypt(const hi_cipher_rsa_pri_enc *rsa_enc,
                                         const hi_u8 *input, hi_u32 in_len,
                                         hi_u8 *output, hi_u32 *output_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_enc == HI_NULL);

    ret = check_rsa_pri_key(&((hi_cipher_rsa_pri_enc *)rsa_enc)->pri_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_rsa_pri_key, ret);
        return ret;
    }

    HI_LOG_CHECK_PARAM(input == HI_NULL);
    HI_LOG_CHECK_PARAM(output == HI_NULL);
    HI_LOG_CHECK_PARAM(output_len == HI_NULL);

    hi_dbg_print_u32(rsa_enc->pri_key.n_len);
    hi_dbg_print_u32(rsa_enc->scheme);
    hi_dbg_print_u32(in_len);

    check_cipher_open();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_FALSE;
    key.klen = rsa_enc->pri_key.n_len;
    key.n = rsa_enc->pri_key.n;
    key.d = rsa_enc->pri_key.d;
    key.p = rsa_enc->pri_key.p;
    key.q = rsa_enc->pri_key.q;
    key.dp = rsa_enc->pri_key.dp;
    key.dq = rsa_enc->pri_key.dq;
    key.qp = rsa_enc->pri_key.qp;

    ret = sys_rsa_encrypt(&key,
                          rsa_enc->scheme,
                          input, in_len,
                          output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_rsa_public_decrypt(const hi_cipher_rsa_pub_enc *rsa_dec,
                                        const hi_u8 *input, hi_u32 in_len,
                                        hi_u8 *output, hi_u32 *output_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_dec == HI_NULL);
    HI_LOG_CHECK_PARAM(input == HI_NULL);
    HI_LOG_CHECK_PARAM(output == HI_NULL);
    HI_LOG_CHECK_PARAM(output_len == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_dec->pub_key.n == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_dec->pub_key.e == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_dec->pub_key.n_len < RSA_MIN_KEY_LEN);
    HI_LOG_CHECK_PARAM(rsa_dec->pub_key.n_len > RSA_MAX_KEY_LEN);
    HI_LOG_CHECK_PARAM(rsa_dec->pub_key.n_len < rsa_dec->pub_key.e_len);

    hi_dbg_print_u32(rsa_dec->scheme);
    hi_dbg_print_u32(in_len);
    hi_dbg_print_u32(rsa_dec->pub_key.n_len);

    check_cipher_open();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_TRUE;
    key.klen = rsa_dec->pub_key.n_len;
    key.n = rsa_dec->pub_key.n;
    cipher_get_pub_exponent(&key.e, rsa_dec);

    ret = sys_rsa_decrypt(&key, rsa_dec->scheme, input, in_len, output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

#ifdef HI_PRODUCT_RSA_SUPPORT
static hi_s32 cipher_hash(hi_cipher_hash_type sha_type,
                          const hi_u8 *in_data, hi_u32 in_data_len,
                          hi_u8 *hash_data, hi_u32 *h_len)
{
    hi_s32 ret;
    hi_handle hash_id;

    ret = sys_hash_start(&hash_id, sha_type, HI_NULL, 0);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_start, ret);
        return ret;
    }

    ret = sys_hash_update(hash_id, in_data, in_data_len, HASH_CHUNCK_SRC_USER);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_update, ret);
        return ret;
    }

    ret = sys_hash_finish(hash_id, hash_data, h_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_hash_finish, ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

hi_s32 hi_mpi_cipher_rsa_sign(const hi_cipher_rsa_sign *rsa_sign,
                              const hi_u8 *in_data, hi_u32 in_data_len,
                              const hi_u8 *hash_data,
                              hi_u8 *out_sign, hi_u32 *out_sign_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };
    hi_u8 hash[HASH_RESULT_MAX_SIZE] = { 0 };
    hi_u8 *ptr = HI_NULL;
    hi_u32 h_len = 0;
    hi_cipher_hash_type sha_type = 0;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_sign == HI_NULL);

    ret = check_rsa_pri_key(&((hi_cipher_rsa_sign *)rsa_sign)->pri_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_rsa_pri_key, ret);
        return ret;
    }

    HI_LOG_CHECK_PARAM(out_sign == HI_NULL);
    HI_LOG_CHECK_PARAM(out_sign_len == HI_NULL);
    HI_LOG_CHECK_PARAM((in_data == HI_NULL) && (hash_data == HI_NULL));

    hi_dbg_print_u32(rsa_sign->scheme);
    hi_dbg_print_u32(rsa_sign->pri_key.n_len);

    check_cipher_open();

    ret = cipher_get_rsa_attr(rsa_sign->scheme, &h_len, &sha_type);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(cipher_get_rsa_attr, ret);
        return ret;
    }

    hi_dbg_print_u32(h_len);
    hi_dbg_print_u32(sha_type);

    /* hash value of context,if NULL, compute hash = Hash(in_data */
    if (hash_data == HI_NULL) {
        ret = cipher_hash(sha_type, in_data, in_data_len, hash, &h_len);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(cipher_hash, ret);
            return ret;
        }
        ptr = hash;
    } else {
        ptr = (hi_u8 *)hash_data;
    }

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_FALSE;
    key.klen = rsa_sign->pri_key.n_len;
    key.n = rsa_sign->pri_key.n;
    key.d = rsa_sign->pri_key.d;
    key.p = rsa_sign->pri_key.p;
    key.q = rsa_sign->pri_key.q;
    key.dp = rsa_sign->pri_key.dp;
    key.dq = rsa_sign->pri_key.dq;
    key.qp = rsa_sign->pri_key.qp;

    ret = sys_rsa_sign_hash(&key, rsa_sign->scheme, ptr, h_len, out_sign, out_sign_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_sign_hash, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_rsa_verify(const hi_cipher_rsa_verify *rsa_verify,
                                const hi_u8 *in_data, hi_u32 in_data_len,
                                const hi_u8 *hash_data,
                                const hi_u8 *in_sign, hi_u32 in_sign_len)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };
    hi_u8 hash[HASH_RESULT_MAX_SIZE] = { 0 };
    hi_u32 h_len = 0;
    hi_u8 *ptr = HI_NULL;
    hi_cipher_hash_type sha_type = 0;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(rsa_verify == HI_NULL);
    HI_LOG_CHECK_PARAM(in_sign == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_verify->pub_key.n == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_verify->pub_key.e == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_verify->pub_key.n_len < RSA_MIN_KEY_LEN);
    HI_LOG_CHECK_PARAM(rsa_verify->pub_key.n_len > RSA_MAX_KEY_LEN);
    HI_LOG_CHECK_PARAM(in_data == HI_NULL && hash_data == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_verify->pub_key.n_len < rsa_verify->pub_key.e_len);

    hi_dbg_print_u32(rsa_verify->scheme);
    hi_dbg_print_u32(rsa_verify->pub_key.n_len);
    hi_dbg_print_u32(rsa_verify->scheme);

    check_cipher_open();

    ret = cipher_get_rsa_attr(rsa_verify->scheme, &h_len, &sha_type);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(cipher_get_rsa_attr, ret);
        return ret;
    }

    hi_dbg_print_u32(sha_type);

    /* hash value of context,if NULL, compute hash = Hash(in_data */
    if (hash_data == HI_NULL) {
        ret = cipher_hash(sha_type, in_data, in_data_len, hash, &h_len);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(cipher_hash, ret);
            return ret;
        }
        ptr = hash;
    } else {
        ptr = (hi_u8 *)hash_data;
    }

    hi_dbg_print_u32(h_len);

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_TRUE;
    key.klen = rsa_verify->pub_key.n_len;
    key.n = rsa_verify->pub_key.n;
    cipher_get_pub_exponent(&key.e, rsa_verify);

    ret = sys_rsa_verify_hash(&key, rsa_verify->scheme, ptr, h_len, in_sign, in_sign_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_verify_hash, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_dh_compute_key(const hi_u8 *p, const hi_u8 *pri_key, const hi_u8 *other_pub_key,
                                    hi_u8 *shared_secret, hi_u32 key_size)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };

    HI_LOG_CHECK_PARAM(p == HI_NULL);
    HI_LOG_CHECK_PARAM(pri_key == HI_NULL);
    HI_LOG_CHECK_PARAM(other_pub_key == HI_NULL);
    HI_LOG_CHECK_PARAM(shared_secret == HI_NULL);
    HI_LOG_CHECK_PARAM(key_size == 0);

    check_cipher_open();

    hi_dbg_print_u32(key_size);

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    key.public = HI_FALSE;
    key.klen = key_size;
    key.n = (hi_u8 *)p;
    key.d = (hi_u8 *)pri_key;

    ret = sys_rsa_encrypt(&key,
                          HI_CIPHER_RSA_ENC_SCHEME_NO_PADDING,
                          other_pub_key, key_size,
                          shared_secret, &key_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_dh_gen_key(const hi_u8 *g, const hi_u8 *p, hi_u8 *input_pri_key,
                                hi_u8 *output_pri_key, hi_u8 *pub_key,
                                hi_u32 key_size)
{
#ifdef HI_PRODUCT_RSA_SUPPORT
    hi_s32 ret;
    cryp_rsa_key key = { 0 };
    hi_u32 i;

    HI_LOG_CHECK_PARAM(p == HI_NULL);
    HI_LOG_CHECK_PARAM(g == HI_NULL);
    HI_LOG_CHECK_PARAM(pub_key == HI_NULL);
    HI_LOG_CHECK_PARAM((input_pri_key == HI_NULL) && (output_pri_key == HI_NULL));
    HI_LOG_CHECK_PARAM(key_size == 0);

    if (p[0] == 0x00) {
        hi_log_err("Invalid P[0], must large than 0!");
        return HI_ERR_CIPHER_INVALID_PARA;
    }

    check_cipher_open();

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    if (input_pri_key == HI_NULL) {
        ret = hi_mpi_cipher_get_multi_random_bytes(output_pri_key, key_size);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(hi_mpi_cipher_get_multi_random_bytes, ret);
            return ret;
        }

        // make sure PrivKey < P
        for (i = 0; i < key_size; i++) {
            if (p[i] == 0x00) {
                output_pri_key[i] = 0x00;
            } else if (output_pri_key[i] < p[i]) {
                break;
            } else {
                output_pri_key[i] = p[0] - 1;
                break;
            }
        }

        key.d = output_pri_key;
    } else {
        key.d = input_pri_key;
    }

    key.public = HI_FALSE;
    key.klen = key_size;
    key.n = (hi_u8 *)p;

    hi_dbg_print_u32(key_size);

    ret = sys_rsa_encrypt(&key, HI_CIPHER_RSA_ENC_SCHEME_NO_PADDING,
                          g, key_size,
                          pub_key, &key_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_rsa_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_sm2_sign(const hi_cipher_sm2_sign *sm2_sign, const hi_u8 *msg,
                              hi_u32 msg_len, hi_u8 r[SM2_LEN_IN_BYTE],
                              hi_u8 s[SM2_LEN_IN_BYTE])
{
#ifdef HI_PRODUCT_SM2_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(sm2_sign == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_sign->d == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_sign->px == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_sign->py == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_sign->id == HI_NULL);
    HI_LOG_CHECK_PARAM(r == HI_NULL);
    HI_LOG_CHECK_PARAM(s == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_sign->id_len > SM2_ID_MAX_LEN);
    if (msg_len > 0) {
        HI_LOG_CHECK_PARAM(msg == HI_NULL);
    }

    check_cipher_open();

    hi_dbg_print_u32(sm2_sign->id_len);
    hi_dbg_print_u32(msg_len);

    ret = sys_sm2_sign(sm2_sign->d, sm2_sign->px, sm2_sign->py,
                       sm2_sign->id, sm2_sign->id_len,
                       msg, msg_len,
                       HASH_CHUNCK_SRC_USER, r, s);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_sm2_sign, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return ret;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_sm2_verify(const hi_cipher_sm2_verify *sm2_verify,
                                const hi_u8 *msg, hi_u32 msg_len,
                                const hi_u8 r[SM2_LEN_IN_BYTE],
                                const hi_u8 s[SM2_LEN_IN_BYTE])
{
#ifdef HI_PRODUCT_SM2_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(sm2_verify == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_verify->px == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_verify->py == HI_NULL);
    HI_LOG_CHECK_PARAM(sm2_verify->id == HI_NULL);
    HI_LOG_CHECK_PARAM(r == HI_NULL);
    HI_LOG_CHECK_PARAM(s == HI_NULL);
    if (msg_len > 0) {
        HI_LOG_CHECK_PARAM(msg == HI_NULL);
    }

    check_cipher_open();
    hi_dbg_print_u32(sm2_verify->id_len);
    hi_dbg_print_u32(msg_len);

    ret = sys_sm2_verify(sm2_verify->px,
                         sm2_verify->py,
                         sm2_verify->id, sm2_verify->id_len,
                         msg, msg_len,
                         HASH_CHUNCK_SRC_USER, r, s);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_sm2_verify, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_sm2_encrypt(const hi_cipher_sm2_enc *sm2_enc, const hi_u8 *msg,
                                 hi_u32 msg_len, hi_u8 *c, hi_u32 *c_len)
{
#ifdef HI_PRODUCT_SM2_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(sm2_enc == HI_NULL);
    HI_LOG_CHECK_PARAM(msg == HI_NULL);
    HI_LOG_CHECK_PARAM(c == HI_NULL);
    HI_LOG_CHECK_PARAM(c_len == HI_NULL);

    check_cipher_open();

    hi_dbg_print_u32(msg_len);

    ret = sys_sm2_encrypt(sm2_enc->px,
                          sm2_enc->py,
                          msg, msg_len,
                          c, c_len);
    if (ret != HI_SUCCESS) {
        hi_dbg_print_u32(*c_len);
        hi_err_print_call_fun_err(sys_sm2_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_sm2_decrypt(const hi_cipher_sm2_dec *sm2_dec, const hi_u8 *c,
                                 hi_u32 c_len, hi_u8 *msg, hi_u32 *msg_len)
{
#ifdef HI_PRODUCT_SM2_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(sm2_dec == HI_NULL);
    HI_LOG_CHECK_PARAM(msg == HI_NULL);
    HI_LOG_CHECK_PARAM(c == HI_NULL);
    HI_LOG_CHECK_PARAM(msg_len == HI_NULL);

    check_cipher_open();

    hi_dbg_print_u32(c_len);

    ret = sys_sm2_decrypt(sm2_dec->d,
                          c, c_len,
                          msg, msg_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_sm2_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_sm2_gen_key(hi_cipher_sm2_key *sm2_key)
{
#ifdef HI_PRODUCT_SM2_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(sm2_key == HI_NULL);

    check_cipher_open();

    ret = sys_sm2_gen_key(sm2_key->d, sm2_key->px, sm2_key->py);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_sm2_gen_key, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_cenc_decrypt_asyn(hi_handle handle, const hi_cipher_cenc *cenc,
                                       hi_mem_handle in_phy_addr, hi_mem_handle out_phy_addr,
                                       hi_u32 byte_length, hi_cipher_cb_done_notify *notify)
{
#ifdef HI_PRODUCT_CENC_SUPPORT
    hi_s32 ret;
    mpi_cenc_dec_msg msg;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(cenc == HI_NULL);
    HI_LOG_CHECK_PARAM(in_phy_addr.mem_handle == 0);
    HI_LOG_CHECK_PARAM(out_phy_addr.mem_handle == 0);
    HI_LOG_CHECK_PARAM(cenc->subsample_num > CENC_SUBSAMPLE_MAX_NUM);

    check_cipher_open();

    ret = memset_s(&msg, sizeof(msg), 0, sizeof(mpi_cenc_dec_msg));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    ret = memcpy_s(&msg.cenc, sizeof(msg.cenc), cenc, sizeof(hi_cipher_cenc));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    ret = memcpy_s(&msg.symc_done, sizeof(msg.symc_done), notify, sizeof(hi_cipher_cb_done_notify));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }
    msg.cipher = handle;
    msg.input.mem_handle  = in_phy_addr.mem_handle;
    msg.input.addr_offset = in_phy_addr.addr_offset;
    msg.output.mem_handle = out_phy_addr.mem_handle;
    msg.output.addr_offset = out_phy_addr.addr_offset;
    msg.length = byte_length;
    msg.cmd    = CENC_MSG_CMD_DEC;

    ret = queue_pool_write(&g_cenc_dec_queue, &msg, sizeof(msg));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(queue_pool_write, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_cipher_cenc_decrypt(hi_handle handle, const hi_cipher_cenc *cenc,
                                  hi_mem_handle in_phy_addr, hi_mem_handle out_phy_addr,
                                  hi_u32 byte_length)
{
#ifdef HI_PRODUCT_CENC_SUPPORT
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(cenc == HI_NULL);
    HI_LOG_CHECK_PARAM(in_phy_addr.mem_handle == 0);
    HI_LOG_CHECK_PARAM(out_phy_addr.mem_handle == 0);
    HI_LOG_CHECK_PARAM(cenc->subsample_num > CENC_SUBSAMPLE_MAX_NUM);

    check_cipher_open();

    ret = sys_cenc_decrypt(handle, cenc, in_phy_addr, out_phy_addr, byte_length);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(sys_cenc_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
#else
    hi_log_err("Unsupport %s\n", __FUNCTION__);
    return HI_FAILURE;
#endif
}

hi_s32 hi_mpi_pbkdf_hmac256(const hi_u8 *hamc_key, hi_u32 hamc_key_len, const hi_u8 *salt, hi_u32 slen,
                            hi_u32 iteration_count, hi_u32 outlen, hi_u8 *out)
{
    hi_s32 ret;
    pbkdf_hmac256_t pfkdf;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(hamc_key == HI_NULL);
    HI_LOG_CHECK_PARAM(salt == HI_NULL);
    HI_LOG_CHECK_PARAM(out == HI_NULL);

    ret = memset_s(&pfkdf, sizeof(pfkdf), 0, sizeof(pfkdf));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    ADDR_VIA(pfkdf.hmac_key) = (hi_u8 *)hamc_key;
    ADDR_VIA(pfkdf.salt) = (hi_u8 *)salt;
    ADDR_VIA(pfkdf.output) = out;
    pfkdf.hmac_key_len = hamc_key_len;
    pfkdf.slen = slen;
    pfkdf.iteration_count = iteration_count;
    pfkdf.outlen = outlen;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_PBKDF2, &pfkdf);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_crypto_self_test(hi_u32 cmd, hi_void *param, hi_u32 size)
{
    hi_s32 ret;
    test_t test;

    hi_dbg_func_enter();

    ret = memset_s(&test, sizeof(test), 0, sizeof(test));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }
    test.cmd = cmd;
    ADDR_VIA(test.param) = param;
    test.size = size;

    ret = CRYPTO_IOCTL(CRYPTO_CMD_TEST, &test);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(CRYPTO_IOCTL, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

/** @} */  /** <!-- ==== API Code end ==== */
