#ifndef _TZCC_H_
#define _TZCC_H_

#define INFRAAO_CFG_BASE (0x10001000)
#define TZCC_BASE        (0x10210000)

extern unsigned int g_pericfg_base_va;
extern unsigned int g_tzcc_base_va;
#define INFRAAO_CFG_VA g_pericfg_base_va
#define TZCC_VA        g_tzcc_base_va

/* for tzcc clock gating */
#define TZCC_CG_SET        (INFRAAO_CFG_VA + 0x088)
#define TZCC_CG_CLEAR      (INFRAAO_CFG_VA + 0x08c)
#define TZCC_CG_STATUS     (INFRAAO_CFG_VA + 0x094)
#define TZCC_SEC_CG_OFFSET (27)
#define TZCC_AO_CG_OFFSET  (28)

/* for tzcc sw reset */
#define TZCC_ALWAYSON_SET   (INFRAAO_CFG_VA + 0x140)
#define TZCC_ALWAYSON_CLR   (INFRAAO_CFG_VA + 0x144)
#define TZCC_SECURECORE_SET (INFRAAO_CFG_VA + 0x150)
#define TZCC_SECURECORE_CLR (INFRAAO_CFG_VA + 0x154)

#define TZCC_ALWAYSON_SET_VALUE   (0x1 << 8)
#define TZCC_ALWAYSON_CLR_VALUE   (0x1 << 8)
#define TZCC_SECURECORE_SET_VALUE (0x1 << 0)
#define TZCC_SECURECORE_CLR_VALUE (0x1 << 0)

#define S_TZCC_OK             (0x0000)
#define S_TZCC_REMAP_REG_FAIL (0x0001)
#define S_TZCC_UNMAP_REG_FAIL (0x0002)
#define S_TZCC_SET_CG_FAIL    (0x0003)
#define S_TZCC_INIT_FAIL      (0x0004)
#define S_TZCC_UNINIT_FAIL    (0x0005)

#define READ32(addr)          *((volatile uint32_t *)(addr))
#define WRITE32(addr, val)    (*((volatile uint32_t *)(addr)) = (val))
#define READBIT(addr, offset) ((READ32(addr) & (0x1 << offset)) >> offset)

typedef struct TZCC_HW_T {
    unsigned int initialized;
    unsigned int reg_mapped;
    unsigned int infraao_cfg_mapped;
    unsigned int isr_received;
} TZCC_HW_T;

typedef struct TZCC_DRAM_BUF_T {
    unsigned int buf_va;
    unsigned int buf_pa;
    unsigned int buf_sz;
} TZCC_DRAM_BUF_T;

#endif /* _TZCC_H_ */
