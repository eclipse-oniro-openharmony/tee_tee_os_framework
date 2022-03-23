/*****************************************************************************

    Copyright (C), 2017, Hisilicon Tech. Co., Ltd.

******************************************************************************
  File Name     : drv_trng.h
  Version       : Initial Draft
  Created       : 2017
  Last Modified :
  Description   :
  Function List :
  History       :
******************************************************************************/
#ifndef __DRV_TRNG_H__
#define __DRV_TRNG_H__

#include <stdint.h>
#define HI_SUCCESS        (0)
typedef unsigned int hi_u32;
typedef int hi_s32;
typedef unsigned int HI_U32;
typedef int HI_S32;
#define TRNG_BASE 0x10090000
#define SEC_CLK 0x120101A0
#define RESET_BIT 2
#define CLK_BIT 3
#define TRNG_OSC_SEL                0x02

#define  HISEC_COM_TRNG_CTRL(base)            (base + 0x200 + (0x00))
#define  HISEC_COM_TRNG_FIFO_DATA(base)       (base + 0x200 + (0x04))
#define  HISEC_COM_TRNG_DATA_ST(base)         (base + 0x200 + (0x08))

/* Define the union hisec_com_trng_ctrl */
typedef union {
    /* Define the struct bits */
    struct {
        hi_u32   osc_sel            :  2;   /* [1..0]  */
        hi_u32   cleardata          :  1;   /* [2]  */
        hi_u32   drbg_enable        :  1;   /* [3]  */
        hi_u32   pre_process_enable :  1;   /* [4]  */
        hi_u32   drop_enable        :  1;   /* [5]  */
        hi_u32   mix_enable         :  1;   /* [6]  */
        hi_u32   post_process_enable:  1;   /* [7]  */
        hi_u32   post_process_depth :  8;   /* [15..8]  */
        hi_u32   reserved0          :  1;   /* [16]  */
        hi_u32   trng_sel           :  2;   /* [18..17]  */
        hi_u32   pos_self_test_en   :  1;   /* [19]  */
        hi_u32   pre_self_test_en     :  1;   /* [20]  */
        hi_u32   reserved1          :  11;  /* [31..21]  */
    } bits;

    /* Define an unsigned member */
    hi_u32    u32;

} hisec_com_trng_ctrl;

/* Define the union hisec_com_trng_data_st */
typedef union {
    /* Define the struct bits */
    struct {
        hi_u32    low_osc_st0        :    1; /* [0]  */
        hi_u32    low_osc_st1        :    1; /* [1]  */
        hi_u32    low_ro_st0         :    1; /* [2]  */
        hi_u32    low_ro_st1         :    1; /* [3]  */
        hi_u32    otp_trng_sel       :    1; /* [4]  */
        hi_u32    reserved0          :    3; /* [7..5]  */
        hi_u32    trng_fifo_data_cnt :    8; /* [15..8]  */
        hi_u32    sic_trng_alarm     :    6; /* [21..16]  */
        hi_u32    sic_trng_bist_alarm:    1; /* [22]  */
        hi_u32    reserved1          :    9; /* [31..23]  */
    } bits;

    /* Define an unsigned member */
    hi_u32    u32;

} hisec_com_trng_data_st;
/*! \rsa capacity, 0-nonsupport, 1-support */
typedef struct {
    hi_u32 trng         : 1 ;    /*!<  Support TRNG */
} trng_capacity;

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API Declaration *****************************/
/** \addtogroup      trng */
/** @{ */  /** <!--[trng]*/


/**
\brief get rand number.
\param[out]  randnum rand number.
\param[in]   timeout time out.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 drv_trng_randnum(hi_u32 *randnum, hi_u32 timeout);

/* map trng base addr */
int32_t map_trng_base_addr(void);

/**
\brief  get the trng capacity.
\param[out] capacity The hash capacity.
\retval     NA.
*/
void drv_trng_get_capacity(trng_capacity *capacity);

/** @} */  /** <!-- ==== API declaration end ==== */

#endif
