/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 *  Description:charlotte cc stub
 *  Create : 2021/01/05
 */
#include <hisi_secboot.h>
#include <hisi_secureboot.h>
#include <cc_power.h>

uint32_t seb_flashread_ram(uint64_t toread_addr, uint8_t *mem_dst,
                                  uint32_t toread_size, void *context)
{
	(void)toread_addr;
	(void)toread_size;
	(void)mem_dst;
	(void)context;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_fillcertpkg(uint64_t cert_address,
                                struct seb_cert_pkg *seb_certpkg)
{
	(void)cert_address;
	(void)seb_certpkg;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_getlcs(uint32_t *lcs_ptr)
{
	*lcs_ptr = SEB_CHIP_MANUFACTURE_LCS;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_imgsecure_verify(seb_flashread_func flashread_func,
                                     struct seb_cert_pkg *seb_certpkg,
                                     void *user_context,
                                     uint32_t *workspace_ptr,
                                     uint32_t workspace_size)
{
	(void)flashread_func;
	(void)seb_certpkg;
	(void)user_context;
	(void)workspace_ptr;
	(void)workspace_size;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_imghash_verify(seb_flashread_func flashread_func,
                                   void *user_context, uint64_t cert_address,
                                   uint32_t *workspace_ptr,
                                   uint32_t workspace_size)
{
	(void)flashread_func;
	(void)cert_address;
	(void)workspace_ptr;
	(void)workspace_size;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_change_compaddr(uint32_t *cert_ptr, uint64_t address,
                                    uint32_t address_index)
{
	(void)cert_ptr;
	(void)address;
	(void)address_index;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_eram_save_restore(uint32_t src_addr, uint32_t dst_addr,
                                      uint32_t block_size,
                                      uint32_t is_srambackup)
{
	(void)src_addr;
	(void)dst_addr;
	(void)block_size;
	(void)is_srambackup;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_basevrl_verify(seb_flashread_func flash_read_func,
                                   void *user_context,
                                   struct seb_cert_pkg *seb_certpkg,
                                   uint32_t *workspace_ptr,
                                   uint32_t workspace_size)
{
	(void)flash_read_func;
	(void)user_context;
	(void)seb_certpkg;
	(void)workspace_ptr;
	(void)workspace_size;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_get_compdata(uint32_t *cert_ptr,
                                 struct seb_comps_info_t *comps_data_ptr)
{
	(void)cert_ptr;
	(void)comps_data_ptr;
	return SECBOOT_RET_SUCCESS;
}

uint32_t seb_eiius_crypto(uint64_t in_addr, uint32_t in_size,
                                 uint64_t out_addr, uint64_t iv_addr,
                                 uint32_t iv_size, uint32_t crypto_direction)
{
	(void)in_addr;
	(void)in_size;
	(void)out_addr;
	(void)iv_addr;
	(void)iv_size;
	(void)crypto_direction;
	return SECBOOT_RET_SUCCESS;
}

int32_t hisi_secs_power_on(void)
{
	return SECBOOT_RET_SUCCESS;
}

int32_t  hisi_secs_power_down(void)
{
	return SECBOOT_RET_SUCCESS;
}

