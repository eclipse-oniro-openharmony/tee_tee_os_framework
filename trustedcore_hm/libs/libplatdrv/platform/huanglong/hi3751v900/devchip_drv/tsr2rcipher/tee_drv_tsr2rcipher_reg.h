/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee tsr2rcipher register
 * Author: sdk
 * Create: 2020-01-23
 */

#ifndef __TEE_DRV_TSR2RCIPHER_REG_H__
#define __TEE_DRV_TSR2RCIPHER_REG_H__

#include "tee_drv_ioctl_tsr2rcipher.h"
#include "tee_drv_tsr2rcipher_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TSC_CHAN_CLEAR_TIMEOUT_CNT  100

#define BITS_PER_REG                32

/* TSR2RCIPHER config regs */
#define TSC_CRG_REGS_IOBASE         0x00A00000
#define TSC_CRG_REGS185_OFFSET      0x02E4

#ifndef readl
#define readl(addr)             (*(volatile u32 *)(addr))
#endif

#ifndef writel
#define writel(val, addr)       (*(volatile u32 *)(addr) = (val))
#endif

#define tsc_read_reg(base, offset)  readl((void *)(uintptr_t)((base) + (offset)))
#define tsc_write_reg(base, offset, value)   writel((value), (void *)(uintptr_t)((base) + (offset)))
#define tsc_com_equal(exp, act) do {                                                    \
    if ((exp) != (act)) {                                                               \
        hi_log_err("write register error, exp=0x%x, act=0x%x\n", (exp), (act)); \
    }                                                                                   \
} while (0)

/* CRG register for tsr2rcipher */
/* Define the union peri_crg185 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    spacc_cken         : 1   ; /* [0]  */
        unsigned int    spacc_srst_req     : 1   ; /* [1]  */
        unsigned int    spacc_clk_sel      : 1   ; /* [2]  */
        unsigned int    tscipher_cken      : 1   ; /* [3]  */
        unsigned int    tscipher_srst_req  : 1   ; /* [4]  */
        unsigned int    reserved_0         : 27  ; /* [31..5]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} peri_crg185;


/* TSR2RCIPHER RX register definition */
#define tsc_read_reg_rx(base, offset)         readl((void *)((base) + TSC_REGS_RX_BASE + (offset)))
#define tsc_write_reg_rx(base, offset, value) writel((value), (void*)((base) + TSC_REGS_RX_BASE + (offset)))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int rx_dsptor_full : 1;  /* [0] */
        unsigned int reserved_0     : 31; /* [31..1] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} rx_dsptor_ctrl;
#define rx_dsptor_ctrl(ch) (0x10 + ((ch) << 6))

typedef union {
    /* define the struct bits  */
    struct {
        unsigned int rx_dsptor_start_addr : 32; /* [31..0] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} rx_dsptor_start_addr;
#define rx_dsptor_start_addr(ch) (0x14 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int rx_dsptor_length : 16; /* [15..0] */
        unsigned int reserved_0       : 15; /* [30..16] */
        unsigned int rx_dsptor_cfg    : 1;  /* [31] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} rx_dsptor_length;
#define rx_dsptor_length(ch) (0x18 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int rx_buf_type      : 1; /* [0] */
        unsigned int reserved_0       : 7; /* [7..1] */
        unsigned int rx_pkt_int_level : 8; /* [15..8] */
        unsigned int reserved_1       : 4; /* [19..16] */
        unsigned int rx_pkt_int_cnt   : 8; /* [27..20] */
        unsigned int rx_session_id    : 4; /* [31..28] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_rx_ctrl;
#define tsc_rx_ctrl(ch) (0x1C + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int reserved_0          : 1;  /* [0] */
        unsigned int iena_rx_dsptor_done : 1;  /* [1] */
        unsigned int iena_rx_pkt_cnt     : 1;  /* [2] */
        unsigned int reserved_1          : 29; /* [31..3] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} iena_rx;
#define iena_rx(ch) (0x24 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int key_id          : 8; /* [7..0] */
        unsigned int reserved_0      : 8; /* [15..8] */
        unsigned int odd_even_sel    : 1; /* [16] */
        unsigned int dsc_type        : 1; /* [17] */
        unsigned int core_sel        : 1; /* [18] */
        unsigned int reserved_1      : 5; /* [23..19] */
        unsigned int tsc_crc_en      : 1; /* [24] */
        unsigned int pl_raw_sel      : 1; /* [25] */
        unsigned int tsc_47_replace  : 1; /* [26] */
        unsigned int reserved_2      : 2; /* [28..27] */
        unsigned int tsc_tx_sec_attr : 1; /* [29] */
        unsigned int tsc_rx_sec_attr : 1; /* [30] */
        unsigned int tsc_chn_en      : 1; /* [31] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_mode_ctrl;
#define tsc_mode_ctrl(ch) (0x30 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int tsc_chn_tee_lock   : 1;  /* [0] */
        unsigned int reserved_0         : 15; /* [15..1] */
        unsigned int tsc_chn_ree_lock   : 1;  /* [16] */
        unsigned int reserved_1         : 15; /* [31..17] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} u_rx_sec_attr;
#define rx_sec_attr(ch) (0x34 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int tsc_clear_chn_id  : 8;  /* [7..0] */
        unsigned int reserved_0        : 8;  /* [15..8] */
        unsigned int tsc_clear_chn_req : 1;  /* [16] */
        unsigned int reserved_1        : 15; /* [31..17] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_clear_req;
#define TSC_CLEAR_REQ                         0x4000


/* TSR2RCIPHER TX register definition */
#define tsc_read_reg_tx(base, offset)         readl((void *)((base) + TSC_REGS_TX_BASE + (offset)))
#define tsc_write_reg_tx(base, offset, value) writel((value), (void*)((base) + TSC_REGS_TX_BASE + (offset)))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int tx_dsptor_full : 1; /* [0] */
        unsigned int reserved_0     : 31; /* [31..1] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tx_dsptor_ctrl;
#define tx_dsptor_ctrl(ch) (0x10 + ((ch) << 6))

typedef union {
    /* define the struct bits  */
    struct {
        unsigned int tx_dsptor_start_addr : 32; /* [31..0] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tx_dsptor_start_addr;
#define tx_dsptor_start_addr(ch) (0x14 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int tx_dsptor_length : 16; /* [15..0] */
        unsigned int reserved_0       : 15; /* [30..16] */
        unsigned int tx_dsptor_cfg    : 1;  /* [31] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tx_dsptor_length;
#define tx_dsptor_length(ch) (0x18 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int tx_buf_type      : 1; /* [0] */
        unsigned int tx_press_dis     : 1; /* [1] */
        unsigned int reserved_0       : 6; /* [7..2] */
        unsigned int tx_pkt_int_level : 8; /* [15..8] */
        unsigned int reserved_1       : 4; /* [19..16] */
        unsigned int tx_pkt_int_cnt   : 8; /* [27..20] */
        unsigned int tx_session_id    : 4; /* [31..28] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_tx_ctrl;
#define tsc_tx_ctrl(ch) (0x1C + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int iraw_tx_buf_afull   : 1;  /* [0] */
        unsigned int iraw_tx_dsptor_done : 1;  /* [1] */
        unsigned int iraw_tx_pkt_cnt     : 1;  /* [2] */
        unsigned int reserved_0          : 29; /* [31..3] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} iraw_tx;
#define iraw_tx(ch) (0x20 + ((ch) << 6))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int iena_tx_buf_afull   : 1; /* [0] */
        unsigned int iena_tx_dsptor_done : 1; /* [1] */
        unsigned int iena_tx_pkt_cnt     : 1; /* [2] */
        unsigned int reserved_0          : 29; /* [31..3] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} iena_tx;
#define iena_tx(ch) (0x24 + ((ch) << 6))


/* TSR2RCIPHER TOP register definition */
#define tsc_read_reg_top(base, offset)         readl((void *)((base) + TSC_REGS_TOP_BASE + (offset)))
#define tsc_write_reg_top(base, offset, value) writel((value), (void*)((base) + TSC_REGS_TOP_BASE + (offset)))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int rx2cpu_iraw     : 1;  /* [0] */
        unsigned int reserved_0      : 7;  /* [7..1] */
        unsigned int tx2cpu_iraw     : 1;  /* [8] */
        unsigned int reserved_1      : 7;  /* [15..9] */
        unsigned int cipher2cpu_iraw : 1;  /* [16] */
        unsigned int reserved_2      : 15; /* [31..17] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_iraw;
#define TSC_IRAW (0x0)

/* Define the union tsc_mmu_sec_en */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    sw_sec_mmu_en         : 1   ; /* [0]  */
        unsigned int    reserved_0            : 7   ; /* [7..1] */
        unsigned int    sw_sec_mmu_type       : 2   ; /* [9..8] */
        unsigned int    reserved_1            : 21  ; /* [30..10] */
        unsigned int    sw_sec_mmu_en_lock    : 1   ; /* [31] */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} tsc_mmu_sec_en;
#define TSC_MMU_SEC_EN                        0x0100    /* secure smmu enable or disable register */

#define TSC_MMU_SEC_TLB                       0x0104
#define tsc_mmu_rx_clr(index)                (0x0120 + ((index) << 2))
#define tsc_mmu_tx_clr(index)                (0x0150 + ((index) << 2))

typedef union {
    /* define the struct bits */
    struct {
        unsigned int sw_mmu_rx_sec_eaddr_h : 4; /* [3..0] */
        unsigned int reserved_0            : 28; /* [31..4] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_mmu_rx_sec_eaddr_h;
#define TSC_MMU_RX_SEC_EADDR_H                0x00A0
#define TSC_MMU_RX_SEC_EADDR_L                0x00A4

typedef union {
    /* define the struct bits */
    struct {
        unsigned int sw_mmu_tx_sec_eaddr_h : 4; /* [3..0] */
        unsigned int reserved_0            : 28; /* [31..4] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_mmu_tx_sec_eaddr_h;
#define TSC_MMU_TX_SEC_EADDR_H                0x00D0
#define TSC_MMU_TX_SEC_EADDR_L                0x00D4

typedef union {
    /* define the struct bits */
    struct {
        unsigned int rx2cpu_iena     : 1;  /* [0] */
        unsigned int reserved_0      : 7;  /* [7..1] */
        unsigned int tx2cpu_iena     : 1;  /* [8] */
        unsigned int reserved_1      : 7;  /* [15..9] */
        unsigned int cipher2cpu_iena : 1;  /* [16] */
        unsigned int reserved_2      : 15; /* [31..17] */
    } bits;

    /* define an unsigned member */
    unsigned int u32;
} tsc_iena;
#define TSC_IENA                              0x8

#ifdef __cplusplus
}
#endif

#endif /* end #ifndef __TEE_DRV_TSR2RCIPHER_REG_H__ */

