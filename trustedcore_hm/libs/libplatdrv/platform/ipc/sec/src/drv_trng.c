/*****************************************************************************

    Copyright (C), 2017, Hisilicon Tech. Co., Ltd.

******************************************************************************
  File Name     : drv_trng_v200.c
  Version       : Initial Draft
  Created       : 2017
  Last Modified :
  Description   :
  Function List :
  History       :
******************************************************************************/
#include "drv_trng.h"
#include <stdlib.h>
#include <hm_mman_ext.h>
#include <iomgr_ext.h>
#include <register_ops.h>
#include <hmlog.h>
#include "hi_common_cipher.h"


/*************************** Internal Structure Definition ****************************/
/** \addtogroup      cipher drivers*/
/** @{*/  /** <!-- [cipher]*/

/*! Define the osc sel */
static void module_enable()
{
    hi_u32 val;
    val = readl(SEC_CLK);
    val |= (1 << CLK_BIT);
    val &= ~(1 << RESET_BIT);
    writel(val, SEC_CLK);
}

hi_s32 drv_trng_randnum(hi_u32 *randnum, hi_u32 timeout)
{
    hisec_com_trng_data_st stat;
    hisec_com_trng_ctrl ctrl;
    static hi_u32 last = 0x0A;
    hi_u32 times = 0;

    ctrl.u32 = readl(HISEC_COM_TRNG_CTRL(TRNG_BASE));
    if (ctrl.u32 != last) {
        module_enable();
        ctrl.bits.mix_enable = 0x00;
        ctrl.bits.drop_enable = 0x00;
        ctrl.bits.pre_process_enable = 0x00;
        ctrl.bits.post_process_enable = 0x00;
        ctrl.bits.post_process_depth = 0x00;
        ctrl.bits.drbg_enable = 0x01;
        ctrl.bits.osc_sel = TRNG_OSC_SEL;
        writel(ctrl.u32, HISEC_COM_TRNG_CTRL(TRNG_BASE));
        last = ctrl.u32;
    }

    if (timeout == 0) { /* unblock */
        /* trng number is valid ? */
        stat.u32 = readl(HISEC_COM_TRNG_DATA_ST(TRNG_BASE));
        if (0x00 == stat.bits.trng_fifo_data_cnt) {
            return HI_ERR_CIPHER_NO_AVAILABLE_RNG;
        }
    } else { /* block */
        while (times++ < timeout) {
            /* trng number is valid ? */
            stat.u32 = readl(HISEC_COM_TRNG_DATA_ST(TRNG_BASE));
            if (0x00 < stat.bits.trng_fifo_data_cnt) {
                break;
            }
        }

        /* time out */
        if (times >= timeout) {
            return HI_ERR_CIPHER_NO_AVAILABLE_RNG;
        }
    }

    /* read valid randnum */
    *randnum = readl(HISEC_COM_TRNG_FIFO_DATA(TRNG_BASE));
    return HI_SUCCESS;
}

/** @} */  /** <!-- ==== API declaration end ==== */
