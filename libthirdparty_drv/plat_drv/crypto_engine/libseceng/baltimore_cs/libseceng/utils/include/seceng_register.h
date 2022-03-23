/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: common register function interface
 * Author     : m00475438
 * Create     : 2018/08/14
 */
#ifndef __SECENG_REGISTER_H__
#define __SECENG_REGISTER_H__
#include "pal_log.h"

/**
 * @brief      : register readback check
 * @param[in]  : addr   register address
 * @param[in]  : value  register value
 * @param[out] : pret   check result
 */
#define REG_RBCHK_ONE(addr, value, pret) do { \
	u32 __reg_value = pal_read_u32(addr); \
	if ((value) == __reg_value) { \
		*(pret) = BSP_RET_OK;\
	} else { \
		*(pret) = ERR_DRV(ERRCODE_NOFOUND); \
		PAL_ERROR("read reg " PAL_FMT_HEX "=" PAL_FMT_HEX \
			  " no match " PAL_FMT_HEX "\n", \
			  addr, __reg_value, value); \
	} \
} while (0)

/**
 * @brief      : write register by readback check
 * @param[in]  : addr   register address
 * @param[in]  : value  register value
 * @param[out] : pret   check result
 */
#define REG_RBCHK_WRITE(addr, value, pret) do { \
	pal_write_u32(value, addr); \
	REG_RBCHK_ONE(addr, value, pret);\
} while (0)

/**
 * @brief      : check if register is value & mask
 * @param[in]  : address    register address
 * @param[in]  : value      register value
 * @param[in]  : mask       register bits mask
 * @param[in]  : timeoutus  timeout, unit(microsecond/us)
 */
err_bsp_t reg_be_value(u32 address, u32 value, u32 mask, u32 timeoutus);

/**
 * @brief      : padding value to register
 * @param[in]  : reg32addr register addr
 * @param[in]  : reg32size register max size
 * @param[in]  : value     register value
 * @param[in]  : reg32num  register size
 */
err_bsp_t reg_padding(u32 reg32addr, u32 reg32size, u32 value, u32 reg32num);

/**
 * @brief      : write register to memory
 * @param[in]  : reg32addr  register address
 * @param[in]  : reg32size  register max size
 * @param[out] : memory     memory addr
 * @param[in]  : wordnum    number of words read
 * @param[in]  : inverted   if inverted is ::SEC_YES,
 *                          the memory data need be inverted by word order
 */
err_bsp_t reg_write(u32 reg32addr, u32 reg32size,
		    const void *memory, u32 wordnum, u32 inverted);

/**
 * @brief      : read data from register to memory
 * @param[in]  : reg32addr  register address
 * @param[in]  : reg32size  register max size
 * @param[out] : memory     memory addr
 * @param[in]  : wordnum    number of words read
 * @param[in]  : inverted   if inverted is ::SEC_YES,
 *                          the memory data need be inverted by word order
 */
err_bsp_t reg_read(u32 reg32addr, u32 reg32size,
		   void *memory, u32 wordnum, u32 inverted);

/**
 * @brief      : padding registers with mask
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[in]  : bakaddr    backup register address
 * @param[in]  : mask       register mask
 * @param[in]  : val        value
 * @param[in]  : reg32num   register size
 * @param[in]  : rand_delay random delay us
 */
err_bsp_t reg_pad_mask(u32 regaddr, u32 reg32size, u32 bakaddr,
		       u32 mask, u32 val, u32 reg32num, u32 rand_delay);

/**
 * @brief      : read registers to memory with mask
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[in]  : bakaddr    backup register address
 * @param[in]  : mask       register mask
 * @param[out] : dst        memory address
 * @param[in]  : wordnum    memory word number
 * @param[in]  : inverted   inverted or not, ::SEC_YES-yes; OTHER:-no
 * @param[in]  : rand_delay random delay us
 */
err_bsp_t reg_read_mask(u32 regaddr, u32 reg32size, u32 bakaddr, u32 mask,
			void *dst, u32 wordnum, u32 inverted, u32 rand_delay);

/**
 * @brief      : write registers from memory with mask
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[in]  : bakaddr    backup register address
 * @param[in]  : mask       register mask
 * @param[in]  : src        memory address
 * @param[in]  : wordnum    memory word number
 * @param[in]  : inverted   inverted or not, ::SEC_YES-yes; OTHER:-no
 * @param[in]  : rand_delay random delay us
 */
err_bsp_t reg_write_mask(u32 regaddr, u32 reg32size, u32 bakaddr, u32 mask,
			 const void *src, u32 wordnum,
			 u32 inverted, u32 rand_delay);

/**
 * @brief      : register readback check by direction
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[in]  : memory     memory address
 * @param[in]  : wordnum    memory word number
 * @param[in]  : inverted   inverted or not, ::SEC_YES-yes; OTHER:-no
 */
err_bsp_t reg_readback_check(u32 reg32addr, u32 reg32size,
			     const void *memory, u32 wordnum, u32 inverted);

/**
 * @brief      : read register by overall small end, word big end
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[in]  : memory     memory address
 * @param[in]  : wordnum    memory word number
 */
err_bsp_t reg_write_bigend(u32 reg32addr, u32 reg32size,
			   const void *memory, u32 wordnum);

/**
 * @brief      : write register by overall small end, word big end
 * @param[in]  : regaddr    register address
 * @param[in]  : reg32size  register max size
 * @param[out] : memory     memory address
 * @param[in]  : wordnum    memory word number
 */
err_bsp_t reg_read_bigend(u32 reg32addr, u32 reg32size,
			  void *memory, u32 wordnum);

#endif/* __SECENG_REGISTER_H__ */

