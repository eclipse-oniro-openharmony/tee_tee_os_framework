/*****************************************************************************

    Copyright (C), 2017, Hisilicon Tech. Co., Ltd.

******************************************************************************
  File Name     : cipher_config.h
  Version       : Initial Draft
  Created       : 2017
  Last Modified :
  Description   :
  Function List :
  History       :
******************************************************************************/
#ifndef __CIPHER_CONFIG_H_
#define __CIPHER_CONFIG_H_

#define  RSA_ENABLE
#define  OTP_SUPPORT
//#define  INT_ENABLE
#define  CIPHER_HASH_SUPPORT
#define  CIPHER_EFUSE_SUPPORT
#define  CIPHER_KLAD_SUPPORT

#define  CIPHER_IRQ_NUMBER                       (59)

#define  CIPHER_RNG_REG_BASE_ADDR_PHY            (0x10090000)
#define  CIPHER_CIPHER_REG_BASE_ADDR_PHY         (0x100C0000)
#define  CIPHER_RSA_REG_BASE_ADDR_PHY            (0x100D0000)

#define  CIPHER_RSA_CRG_ADDR_PHY                 (0x120101A0)
#define  RSA_CRG_CLOCK_BIT                       (0x01 << 7)
#define  RSA_CRG_RESET_BIT                       (0x01 << 6)
#define  CIPHER_SPACC_CRG_ADDR_PHY               (0x120101A0)
#define  SPACC_CRG_CLOCK_BIT                     (0x01 << 9)
#define  SPACC_CRG_RESET_BIT                     (0x01 << 8)
#define  CIPHER_RNG_CRG_ADDR_PHY                 (0x120101A0)
#define  RNG_CRG_CLOCK_BIT                       (0x01 << 3)
#define  RNG_CRG_RESET_BIT                       (0x01 << 2)

#define  CIPHER_KLAD_REG_BASE_ADDR_PHY           (0x10070000)
#define  CIPHER_OTP_REG_BASE_ADDR_PHY            (0x100B0000)
#define  CIPHER_KLAD_CRG_ADDR_PHY                (0x120101A0)

#define  KLAD_CRG_CLOCK_BIT                      (0x01 << 1)
#define  KLAD_CRG_RESET_BIT                      (0x01 << 0)

#endif

