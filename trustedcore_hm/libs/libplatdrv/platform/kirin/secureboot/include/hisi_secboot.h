/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: defination of ERR CODE/struct/function for secboot
 * Create: 2013/5/16
 */

#ifndef __HISI_SECBOOT_H__
#define __HISI_SECBOOT_H__

#include <stdint.h>

#define SEB_AES_CMAC_RESULT_BYTES           0x10UL
#define SIZE_OF_ADD_DATA_PAIR_BYTES         12
#define SEB_MAX_NONCE_BYTES                 (2 * sizeof(uint32_t))

#define SEB_CHIP_MANUFACTURE_LCS            0x0
#define SEB_DEVICE_MANUFACTURE_LCS          0x1
#define SEB_SECURITY_DISABLED_LCS           0x3
#define SEB_SECURE_LCS                      0x5
#define SEB_RMA_LCS                         0x7
#define SEB_SECURITY_INVALID_LCS            0x8
#define SEB_INVALID_ADDR                    0xFFFFFFFFFFFFFFFF
#define SEB_INVALID_VALUE                   0xFFFFFFFF

#define SEB_INVALID_KEY1_CERT               0x000F0001
#define SEB_INVALID_KEY1_CERT_TYPE          0x000F0002
#define SEB_INVALID_KEY1_CERT_ADDR          0x000F0003
#define SEB_INVALID_KEY2_CERT               0x000F0004
#define SEB_INVALID_KEY2_CERT_TYPE          0x000F0005
#define SEB_INVALID_CONT_CERT               0x000F0006
#define SEB_INVALID_CONT_CERT_TYPE          0x000F0007
#define SEB_INVALID_CONT_CERT_ADDR          0x000F0008
#define SEB_EMPTY_VALUE                     0x0

/* Data on s/w components */
struct seb_comps_info_t {
	/* Num of s/w comps */
	uint32_t comps_num;
	/* Indicator if SW image is encrypted */
	uint8_t is_comps_encryted;
	/* nonce */
	uint8_t nonce[SEB_MAX_NONCE_BYTES];
	/* pointer to start of sw comps data */
	uint32_t *p_comps_data;
};

/* Data struct for SB Certificate package */
struct seb_cert_pkg {
	uint64_t keycert1_addr;
	uint64_t keycert2_addr;
	uint64_t concert_addr;
};

typedef uint32_t (*seb_flashread_func)(
	uint64_t toread_addr, /* Flash address to read from */
	uint8_t *mem_dst, /* memory destination to read the data to */
	uint32_t toread_size, /* size to read from Flash (in bytes) */
	void *context); /* context for user's needs */

/* the follow are exports from cc source */
extern uint32_t seb_flashread_ram(uint64_t toread_addr, uint8_t *mem_dst,
				  uint32_t toread_size, void *context);
extern uint32_t seb_fillcertpkg(uint64_t cert_address,
				struct seb_cert_pkg *seb_certpkg);
extern uint32_t seb_getlcs(uint32_t *lcs_ptr);
extern uint32_t seb_imgsecure_verify(seb_flashread_func flashread_func,
				     struct seb_cert_pkg *seb_certpkg,
				     void *user_context,
				     uint32_t *workspace_ptr,
				     uint32_t workspace_size);
extern uint32_t seb_imghash_verify(seb_flashread_func flashread_func,
				   void *user_context, uint64_t cert_address,
				   uint32_t *workspace_ptr,
				   uint32_t workspace_size);
extern uint32_t seb_change_compaddr(uint32_t *cert_ptr, uint64_t address,
				    uint32_t address_index);
extern uint32_t seb_eram_save_restore(uint32_t src_addr, uint32_t dst_addr,
				      uint32_t block_size,
				      uint32_t is_srambackup);
extern uint32_t seb_basevrl_verify(seb_flashread_func flash_read_func,
				   void *user_context,
				   struct seb_cert_pkg *seb_certpkg,
				   uint32_t *workspace_ptr,
				   uint32_t workspace_size);
extern uint32_t seb_get_compdata(uint32_t *cert_ptr,
				 struct seb_comps_info_t *comps_data_ptr);
extern uint32_t seb_eiius_crypto(uint64_t in_addr, uint32_t in_size,
				 uint64_t out_addr, uint64_t iv_addr,
				 uint32_t iv_size, uint32_t crypto_direction);

#endif
