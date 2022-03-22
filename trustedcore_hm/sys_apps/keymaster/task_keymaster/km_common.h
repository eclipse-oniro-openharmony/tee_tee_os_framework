/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: keymaster common functions header
 * Create: 2016-05-04
 */
#ifndef __KM_COMMON_H
#define __KM_COMMON_H

#include <dlist.h>
#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "crypto_wrapper.h"

/* ASN.1 object types */
#define KM_ASN1_SEQ        0x30 /* sequence object */
#define KM_ASN1_SET        0x31
#define KM_ASN1_BOOLEAN    0x01
#define KM_ASN1_INT        0x02 /* integer */
#define KM_ASN1_BIT_STRING 0x03 /* bit string */
#define KM_ASN1_OCTSTR     0x04 /* octet string */
#define KM_ASN1_NULL       0x05 /* null */
#define KM_ASN1_ENUMERATED 0x0a

#define byte_after_bit_shift(x, n) (uint8_t)(((x) >> (n)) & 0xFF)

#define convert32l(x, y)                             \
    do {                                             \
        (y)[0] = byte_after_bit_shift(x, 24);        \
        (y)[1] = byte_after_bit_shift(x, 16);        \
        (y)[2] = byte_after_bit_shift(x, 8);         \
        (y)[3] = byte_after_bit_shift(x, 0);         \
    } while (0)

#define convert64l(x, y)  do {                       \
        (y)[0] = byte_after_bit_shift(x, 56);        \
        (y)[1] = byte_after_bit_shift(x, 48);        \
        (y)[2] = byte_after_bit_shift(x, 40);        \
        (y)[3] = byte_after_bit_shift(x, 32);        \
        (y)[4] = byte_after_bit_shift(x, 24);        \
        (y)[5] = byte_after_bit_shift(x, 16);        \
        (y)[6] = byte_after_bit_shift(x, 8);         \
        (y)[7] = byte_after_bit_shift(x, 0);         \
    } while (0)


typedef struct {
    /* Read data from file
     *
     * @para filename:  The path name of the file
     * @para buf:       The buffer used to store the content readed from the file
     * @len:            The size count in buffer trying to read from the file
     * @return  <0  read error
     *          >=0 real read length
     * */
    int (*read)(const char *filename, uint8_t *buf, uint32_t len);

    /* Write data into file
     *
     * @para filename:  The path name of the file
     * @para buf:       The content which you want write into the file
     * @len:            The size of the content
     * @return  TEE_SUCCESS  ok
     *          others error
     * */
    int (*write)(const char *filename, uint8_t *buf, uint32_t len);

    /* Delete file
     *
     * @para filename:  The path name of the file
     * @return  TEE_SUCCESS  ok
     *          others error
     * */
    int (*remove)(const char *filename);

    /* Get file size
     *
     * @para filename:  The path name of the file
     * @return  < 0 error
     *          >=0 The size of the file
     * */
    int (*filesize)(const char *filename);

    /* fs using
     */
    int fs_using;
} file_operations_t;
/* dump hex format text */
#ifdef DUMP_MSG
void dump_msg(const char *info, uint8_t *data, int32_t len);
#endif
/* get next int value */
int32_t get_next_int4(uint8_t **in);

/* asn1 format to gp format sign data */
int32_t ec_sig_gp_format(uint8_t *in, uint32_t *in_len, uint32_t key_size_in_bits);

/* free cert chain */
void km_free_cert_chain(keymaster_cert_chain_t *chain);

/* sign with attest key, input is buf. */
int32_t sign_with_attest_key(const keymaster_blob_t *in, keymaster_blob_t *out, int src, int alg);

/* get cert entry */
int32_t get_cert_entry(int src, int32_t alg, int32_t cert_num, keymaster_blob_t *cert_entry);

/* convert private dx format to sw struct */
int covert_prvkey_dx2sw(int alg, const void *crys_pkey, const void *sw_pkey);

/* ASN.1 format tlv */
void insert_tlv(uint32_t type, uint32_t len, const uint8_t *value, uint8_t **buf, uint32_t *buf_len);

/* ASN.1 explicit tag insert */
void insert_explicit_tlv(uint32_t type, uint32_t len, uint8_t *value, uint8_t **buf, uint32_t *buf_len, uint32_t tag);

int32_t build_rot_field(uint8_t *rot_buf, uint32_t *rot_len);
TEE_Result gp_buffer_to_key_obj(uint8_t *buffer, uint32_t buffer_len, TEE_ObjectHandle key_obj);
TEE_Result key_object_to_buffer(const TEE_ObjectHandle key_obj, uint8_t *kb, uint32_t *buffer_len);
file_operations_t *get_file_operation_info();
void erase_free_blob(keymaster_blob_t *blob);
void free_blob(keymaster_blob_t *blob);
int init_km_mutex(void);
void destroy_km_mutex(void);

/* set file ops of SFS or RPMB */
int32_t set_file_operation(void);
bool is_buff_zero(const uint8_t *buff, uint32_t len);
#endif
