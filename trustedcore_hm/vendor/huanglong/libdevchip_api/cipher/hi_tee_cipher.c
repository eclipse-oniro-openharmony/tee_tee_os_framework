/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee cipher
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_tee_cipher.h"
#include "hi_mpi_cipher.h"
#include "user_osal_lib.h"

hi_s32 hi_tee_cipher_init(hi_void)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_init();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_init, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_deinit(hi_void)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_deinit();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_deinit, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_create(hi_handle *cipher, const hi_tee_cipher_attr *cipher_attr)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_create_handle(cipher, (hi_cipher_attr *)cipher_attr);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_create_handle, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_destroy(hi_handle cipher)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_destroy_handle(cipher);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_destroy_handle, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_get_keyslot_handle(hi_handle cipher, hi_handle *keyslot)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_get_keyslot_handle(cipher, keyslot);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_get_keyslot_handle, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_set_config(hi_handle cipher, const hi_tee_cipher_config *cipher_config)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_config_handle_ex(cipher, (hi_cipher_ctrl_ex *)cipher_config);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_config_handle_ex, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_get_config(hi_handle handle, const hi_tee_cipher_config *cipher_config)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_get_handle_config(handle, (hi_cipher_ctrl *)cipher_config);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_get_handle_config, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}
hi_s32 hi_tee_cipher_encrypt(hi_handle cipher,
                             hi_mem_handle src_buf, hi_mem_handle dest_buf,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_encrypt(cipher, src_buf, dest_buf, byte_length, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_decrypt(hi_handle cipher,
                             hi_mem_handle src_buf, hi_mem_handle dest_buf,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_decrypt(cipher, src_buf, dest_buf, byte_length, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_encrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg, hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_encrypt_multi(cipher, (hi_cipher_data *)data_pkg, data_pkg_num, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_encrypt_multi, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_decrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg, hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_decrypt_multi(cipher, (hi_cipher_data *)data_pkg, data_pkg_num, data_dir);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_decrypt_multi, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_get_tag(hi_handle cipher, hi_u8 *tag, hi_u32 *tag_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_get_tag(cipher, tag, tag_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_get_tag, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}


hi_s32 hi_tee_cipher_get_random_number(hi_u32 *random_number)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_get_random_number(random_number, 0);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_get_random_number, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_get_multi_random_bytes(hi_u32 bytes, hi_u8 *random_byte)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_get_multi_random_bytes(random_byte, bytes);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_get_multi_random_bytes, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_hash_init(hi_tee_cipher_hash_attr *cipher_attr, hi_handle *hash)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_hash_init((hi_cipher_hash_attr *)cipher_attr, hash);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_hash_init, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_hash_update(hi_handle hash, const hi_u8 *input_data, hi_u32 input_data_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_hash_update(hash, input_data, input_data_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_hash_update, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_hash_final(hi_handle hash, hi_u8 *hash_buf, hi_u32 *hash_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_hash_final(hash, hash_buf, hash_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_hash_final, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_public_encrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_rsa_public_encrypt((hi_cipher_rsa_pub_enc *)param,
                                           input, input_len, output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_public_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_private_decrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_rsa_private_decrypt((hi_cipher_rsa_pri_enc *)param,
                                            input, input_len, output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_private_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_private_encrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_rsa_private_encrypt((hi_cipher_rsa_pri_enc *)param,
                                            input, input_len, output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_private_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_public_decrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_rsa_public_decrypt((hi_cipher_rsa_pub_enc *)param,
                                           input, input_len, output, output_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_public_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_sign(hi_tee_cipher_rsa_sign_param *param, hi_tee_cipher_rsa_sign_verify_data *rsa_sign_data)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(rsa_sign_data == HI_NULL);
    ret = hi_mpi_cipher_rsa_sign((hi_cipher_rsa_sign *)param, rsa_sign_data->input, rsa_sign_data->input_len,
                                 rsa_sign_data->hash_data, rsa_sign_data->sign, rsa_sign_data->sign_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_sign, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_rsa_verify(hi_tee_cipher_rsa_verify_param *param,
                                hi_tee_cipher_rsa_sign_verify_data *rsa_verify_data)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(rsa_verify_data == HI_NULL);
    HI_LOG_CHECK_PARAM(rsa_verify_data->sign_len == HI_NULL);
    ret = hi_mpi_cipher_rsa_verify((hi_cipher_rsa_verify *)param, rsa_verify_data->input, rsa_verify_data->input_len,
                                   rsa_verify_data->hash_data, rsa_verify_data->sign,
                                   *(rsa_verify_data->sign_len));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_rsa_verify, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_sm2_sign(hi_tee_cipher_sm2_sign_param *param, hi_tee_cipher_sm2_sign_verify_data *sm2_sign_data)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(sm2_sign_data == HI_NULL);

    ret = hi_mpi_cipher_sm2_sign((hi_cipher_sm2_sign *)param, sm2_sign_data->msg, sm2_sign_data->msg_len,
                                 sm2_sign_data->sign_r, sm2_sign_data->sign_s);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_sm2_sign, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_sm2_verify(hi_tee_cipher_sm2_verify_param *param,
                                const hi_tee_cipher_sm2_sign_verify_data *sm2_verify_data)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(sm2_verify_data == HI_NULL);

    ret = hi_mpi_cipher_sm2_verify((hi_cipher_sm2_verify *)param, sm2_verify_data->msg, sm2_verify_data->msg_len,
                                   sm2_verify_data->sign_r, sm2_verify_data->sign_s);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_sm2_verify, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_sm2_encrypt(hi_tee_cipher_sm2_enc_param *param, hi_u8 *msg, hi_u32 msg_len,
                                 hi_u8 *c, hi_u32 *c_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_sm2_encrypt((hi_cipher_sm2_enc *)param, msg, msg_len, c, c_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_sm2_encrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_sm2_decrypt(hi_tee_cipher_sm2_dec_param *param, hi_u8 *c, hi_u32 c_len,
                                 hi_u8 *msg, hi_u32 *msg_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_sm2_decrypt((hi_cipher_sm2_dec *)param, c, c_len, msg, msg_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_sm2_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_sm2_gen_key(hi_tee_cipher_sm2_key *sm2_key)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_sm2_gen_key((hi_cipher_sm2_key *)sm2_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_sm2_gen_key, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_cenc_decrypt(hi_handle cipher, const hi_tee_cipher_cenc_param *param,
                                  hi_tee_cenc_decrypt_data *cenc_decrypt_data)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(cenc_decrypt_data == HI_NULL);

    if (cenc_decrypt_data->symc_done != HI_NULL) {
        ret = hi_mpi_cipher_cenc_decrypt_asyn(cipher, (hi_cipher_cenc *)param, cenc_decrypt_data->src_buf,
                                              cenc_decrypt_data->dest_buf, cenc_decrypt_data->byte_length,
                                              (hi_cipher_cb_done_notify *)(cenc_decrypt_data->symc_done));
    } else {
        ret = hi_mpi_cipher_cenc_decrypt(cipher, (hi_cipher_cenc *)param, cenc_decrypt_data->src_buf,
                                         cenc_decrypt_data->dest_buf, cenc_decrypt_data->byte_length);
    }

    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_cenc_decrypt, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_dh_compute_key(hi_u8 *p, hi_u8 *priv_key, hi_u8 *other_pub_key,
                                    hi_u8 *shared_secret, hi_u32 key_size)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_mpi_cipher_dh_compute_key(p, priv_key, other_pub_key, shared_secret, key_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_dh_compute_key, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_dh_gen_key(hi_tee_cipher_dh_gen_key_data *param)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    HI_LOG_CHECK_PARAM(param == HI_NULL);

    ret = hi_mpi_cipher_dh_gen_key(param->g, param->p, param->input_priv_key, param->output_priv_key,
                                   param->pub_key, param->key_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_cipher_dh_gen_key, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_tee_cipher_pbkdf2(const hi_tee_cipher_pbkdf2_param *param, hi_u8 *output, hi_u32 output_len)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(param == HI_NULL);
    HI_LOG_CHECK_PARAM(output == HI_NULL);

    ret = hi_mpi_pbkdf_hmac256(param->hmac_key, param->hmac_key_len, param->salt,
                               param->slen, param->iteration_count, param->key_length, output);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_mpi_pbkdf_hmac256, ret);
        return ret;
    }

    hi_dbg_func_exit();

    return ret;
}

hi_s32 hi_tee_cipher_test(hi_u32 cmd, hi_void *param, hi_u32 param_size)
{
    return hi_mpi_crypto_self_test(cmd, param, param_size);
}

/** @} */ /** <!-- ==== compat code end ==== */
