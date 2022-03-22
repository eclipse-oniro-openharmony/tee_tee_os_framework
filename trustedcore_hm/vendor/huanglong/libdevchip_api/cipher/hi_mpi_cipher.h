/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee mpi cipher head file
 * Author: cipher group
 * Create: 2019-12-11
 */

#ifndef __HI_MPI_CIPHER_H__
#define __HI_MPI_CIPHER_H__

#include "hi_tee_cipher.h"
#include "hi_tee_drv_cipher.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef hi_void (*hi_cipher_done_notify_func)(hi_handle cipher, hi_s32 result, hi_void *user_data, hi_u32 data_size);

typedef struct hicipher_cb_done_notify {
    hi_cipher_done_notify_func symc_done;
    hi_void *user_data;
    hi_u32 data_size;
} hi_cipher_cb_done_notify;

hi_s32 hi_mpi_cipher_init(hi_void);
hi_s32 hi_mpi_cipher_deinit(hi_void);
hi_s32 hi_mpi_cipher_create_handle(hi_handle *handle, const hi_cipher_attr *cipher_attr);
hi_s32 hi_mpi_cipher_destroy_handle(hi_handle handle);
hi_s32 hi_mpi_cipher_get_keyslot_handle(hi_handle cipher, hi_handle *keyslot);
hi_s32 hi_mpi_cipher_config_handle(hi_handle handle, const hi_cipher_ctrl *ctrl);
hi_s32 hi_mpi_cipher_config_handle_ex(hi_handle handle, const hi_cipher_ctrl_ex *ctrl_ex);
hi_s32 hi_mpi_cipher_encrypt(hi_handle handle, hi_mem_handle src_phy_addr, hi_mem_handle dest_phy_addr,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir);
hi_s32 hi_mpi_cipher_decrypt(hi_handle handle, hi_mem_handle src_phy_addr, hi_mem_handle dest_phy_addr,
                             hi_u32 byte_length, hi_tee_cipher_data_dir data_dir);
hi_s32 hi_mpi_cipher_encrypt_multi(hi_handle handle, const hi_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num, hi_tee_cipher_data_dir data_dir);
hi_s32 hi_mpi_cipher_decrypt_multi(hi_handle handle, const hi_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num, hi_tee_cipher_data_dir data_dir);
hi_s32 hi_mpi_cipher_get_handle_config(hi_handle handle_handle, hi_cipher_ctrl *ctrl);
hi_s32 hi_mpi_cipher_hash_init(const hi_cipher_hash_attr *hash_attr, hi_handle *handle);
hi_s32 hi_mpi_cipher_hash_update(hi_handle handle, const hi_u8 *input_data, hi_u32 input_data_len);
hi_s32 hi_mpi_cipher_hash_final(hi_handle hash_handle, hi_u8 *output_hash, hi_u32 *hash_len);
hi_s32 hi_mpi_cipher_get_tag(hi_handle handle, hi_u8 *tag, hi_u32 *tag_len);
hi_s32 hi_mpi_cipher_get_random_number(hi_u32 *random_number, hi_u32 time_out_us);
hi_s32 hi_mpi_cipher_get_multi_random_bytes(hi_u8 *random_byte, hi_u32 bytes);
hi_s32 hi_mpi_cipher_rsa_public_encrypt(const hi_cipher_rsa_pub_enc *rsa_enc,
                                        const hi_u8 *input, hi_u32 in_len,
                                        hi_u8 *output, hi_u32 *out_len);

hi_s32 hi_mpi_cipher_rsa_private_decrypt(const hi_cipher_rsa_pri_enc *rsa_dec,
                                         const hi_u8 *input, hi_u32 in_len,
                                         hi_u8 *output, hi_u32 *out_len);

hi_s32 hi_mpi_cipher_rsa_sign(const hi_cipher_rsa_sign *rsa_sign,
                              const hi_u8 *in_data, hi_u32 in_data_len,
                              const hi_u8 *hash_data,
                              hi_u8 *out_sign, hi_u32 *out_sign_len);

hi_s32 hi_mpi_cipher_rsa_verify(const hi_cipher_rsa_verify *rsa_verify,
                                const hi_u8 *in_data, hi_u32 in_data_len,
                                const hi_u8 *hash_data,
                                const hi_u8 *in_sign, hi_u32 in_sign_len);

hi_s32 hi_mpi_cipher_rsa_private_encrypt(const hi_cipher_rsa_pri_enc *rsa_enc,
                                         const hi_u8 *input, hi_u32 in_len,
                                         hi_u8 *output, hi_u32 *out_len);

hi_s32 hi_mpi_cipher_rsa_public_decrypt(const hi_cipher_rsa_pub_enc *rsa_dec,
                                        const hi_u8 *input, hi_u32 in_len,
                                        hi_u8 *output, hi_u32 *out_len);

hi_s32 hi_mpi_cipher_sm2_sign(const hi_cipher_sm2_sign *sm2_sign, const hi_u8 *msg, hi_u32 msg_len,
                              hi_u8 *r, hi_u8 *s);
hi_s32 hi_mpi_cipher_sm2_verify(const hi_cipher_sm2_verify *sm2_verify, const hi_u8 *msg,
                                hi_u32 msg_len, const hi_u8 *r, const hi_u8 *s);
hi_s32 hi_mpi_cipher_sm2_encrypt(const hi_cipher_sm2_enc *sm2_enc, const hi_u8 *msg, hi_u32 msg_len,
                                 hi_u8 *c, hi_u32 *c_len);
hi_s32 hi_mpi_cipher_sm2_decrypt(const hi_cipher_sm2_dec *sm2_dec, const hi_u8 *c, hi_u32 c_len,
                                 hi_u8 *msg, hi_u32 *msg_len);
hi_s32 hi_mpi_cipher_sm2_gen_key(hi_cipher_sm2_key *sm2_key);

hi_s32 hi_mpi_cipher_rsa_gen_key(hi_u32 num_bits, hi_u32 exponent,
                                 hi_cipher_rsa_pri_key *rsa_pri_key);

hi_s32 hi_mpi_cipher_rsa_compute_crt_params(hi_u32 num_bits, hi_u32 exponent, hi_u8 *p,
                                            hi_u8 *q, hi_u8 *dp, hi_u8 *dq, hi_u8 *qp);

hi_s32 hi_mpi_cipher_dh_compute_key(const hi_u8 *p, const hi_u8 *pri_key, const hi_u8 *other_pub_key,
                                    hi_u8 *shared_secret, hi_u32 key_size);

hi_s32 hi_mpi_cipher_dh_gen_key(const hi_u8 *g, const hi_u8 *p, hi_u8 *input_Pri_key,
                                hi_u8 *output_pri_key, hi_u8 *pub_key,
                                hi_u32 key_size);

hi_s32 hi_mpi_cipher_cenc_decrypt(hi_handle handle, const hi_cipher_cenc *cenc,
                                  hi_mem_handle in_phy_addr, hi_mem_handle out_phy_addr, hi_u32 byte_length);

hi_s32 hi_mpi_pbkdf_hmac256(const hi_u8 *hamc_key, hi_u32 hamc_key_len, const hi_u8 *salt, hi_u32 slen,
                            hi_u32 iteration_count, hi_u32 outlen, hi_u8 *out);

hi_s32 hi_mpi_cipher_cenc_decrypt_asyn(hi_handle handle, const hi_cipher_cenc *cenc,
                                       hi_mem_handle in_phy_addr, hi_mem_handle out_phy_addr,
                                       hi_u32 byte_length, hi_cipher_cb_done_notify *notify);

hi_s32 hi_mpi_crypto_self_test(hi_u32 cmd, hi_void *param, hi_u32 size);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __hi_mpi_cipher_h__ */
