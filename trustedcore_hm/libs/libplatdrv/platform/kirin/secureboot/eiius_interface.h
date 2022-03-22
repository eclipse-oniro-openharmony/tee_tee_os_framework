/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: eiius driver
 * Create: 2020/04/28
 */

#ifndef __EIIUS_INTERFACE_H_
#define __EIIUS_INTERFACE_H_

#include <stdint.h>
#include "mem_page_ops.h"

#define SZ_1M                   0x100000
#define EIIUS_VRL_SIZE          0x10000
#define EIIUS_AES_IV_SIZE       16

/* If you modfied the address type, please also sync it to TA. */
enum eiius_addr_type_t {
	EIIUS_ADDR_WORKSPACE1_TYPE,
	EIIUS_ADDR_WORKSPACE2_TYPE,
	EIIUS_ADDR_INCR_DATA_TYPE,
	EIIUS_ADDR_INCR_VRL_TYPE,
	EIIUS_ADDR_O_I_VRL_TYPE,
	EIIUS_ADDR_N_I_VRL_TYPE,
	EIIUS_ADDR_STUB_TYPE,
	EIIUS_ADDR_RESERVED_TYPE,
	EIIUS_ADDR_MAX_TYPE,
};

/* If you modfied the error code, please also sync it to TA. */
enum eiius_drv_proc_err {
	EIIUS_DRV_SUCCESS = 0,
	EIIUS_DRV_ERR_PARA = 0xF01,

	EIIUS_DRV_ERR_MEM_MAP = 0xF02,
	EIIUS_DRV_ERR_ADDR_MAPPED = 0xF03,
	EIIUS_DRV_ERR_MEM_UNMAP = 0xF04,

	EIIUS_DRV_ERR_TA_PID = 0xF05,
	EIIUS_DRV_ERR_DRV_PID = 0xF06,

	EIIUS_DRV_ERR_DATA_TOO_BIG = 0xF07,
	EIIUS_DRV_ERR_COPY_DATA = 0xF08,

	EIIUS_DRV_ERR_INCR_UPDATE = 0xF09,

	EIIUS_DRV_ERR_LCS_NONE = 0xF0A,
};

enum eiius_crypto_type {
	EIIUS_DECRYPTO_DATA,
	EIIUS_ENCRYPTO_DATA,
	EIIUS_CRYPTO_MAX,
};

uint32_t eiius_image_verify(paddr_t data_paddr,
			    paddr_t vrl_paddr,
			    uint32_t maxsize,
			    uint32_t is_decrypto);

uint32_t eiius_encrypto_ctr(paddr_t in_vaddr,
			    paddr_t out_vaddr,
			    uint32_t in_size,
			    uint8_t *iv,
			    uint32_t iv_size,
			    uint32_t mode);

uint32_t eiius_get_paddr(uint32_t *low_paddr,
			 uint32_t *high_paddr,
			 uint32_t *p_size,
			 uint32_t addr_type);

uint32_t eiius_secure_memory_map(paddr_t paddr,
				 uint32_t size,
				 uint32_t *vaddr,
				 uint32_t secure_mode,
				 uint32_t cache_mode);

uint32_t eiius_secure_memory_unmap(uint32_t vaddr, uint32_t size);

#endif
