

#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"

#include <sre_typedef.h>
#include <register_ops.h> // writel
#include <sre_sys.h>
#include <mem_ops.h>
#include <sre_hwi.h>
#include "tee_defines.h"

#include "stdint.h"
#include "drv_module.h"
#include "libhwsecurec/securec.h"

#include "npu_public_sec.h"
#include "npu_smmu_sec.h"

#define SMMU_MSTR_WDATA_BURST (0x00000010)
#define SMMU_MSTR_WR_VA_OUT_OF_128BYTE (0x00000008)
#define SMMU_MSTR_WR_VA_OUT_OF_BOUNDARY (0x00000004)
#define SMMU_MSTR_RD_VA_OUT_OF_128BYTE (0x00000002)
#define SMMU_MSTR_RD_VA_OUT_OF_BOUNDARY (0x00000001)

#define NPU_SMMU_WR_ERR_BUFF_LEN (128)
#define DTS_SMMU_NAME "smmu"
#define SMMU_MSTR_DEBUG_CONFIG_WR (16)
#define SMMU_MSTR_DEBUG_CONFIG_CS (17)
#define SMMU_MSTR_SET_DEBUG_PORT ((1 << SMMU_MSTR_DEBUG_CONFIG_WR) | (1 << SMMU_MSTR_DEBUG_CONFIG_CS))
#define SMMU_MSTR_INPUT_SEL_REGISTER (0x00000003)
#define SMMU_MSTR_INPUT_SEL_REGISTER_DEFAULT (0x00000000)
#define SMMU_MSTR_ALL_STREAM_IS_END_ACK (0x0000000f)
#define SMMU_MSTR_GLB_BYPASS_NORMAL_MODE (0x00000000)
#define SMMU_MSTR_GLB_BYPASS_DIRECTLY_MODE (0x00000001)
#define SMMU_MSTR_WDATA_BURST (0x00000010)
#define SMMU_MSTR_WR_VA_OUT_OF_128BYTE (0x00000008)
#define SMMU_MSTR_WR_VA_OUT_OF_BOUNDARY (0x00000004)
#define SMMU_MSTR_RD_VA_OUT_OF_128BYTE (0x00000002)
#define SMMU_MSTR_RD_VA_OUT_OF_BOUNDARY (0x00000001)
#define SMMU_MSTR_INTCLR_ALL (SMMU_MSTR_WDATA_BURST \
    | SMMU_MSTR_WR_VA_OUT_OF_128BYTE \
    | SMMU_MSTR_WR_VA_OUT_OF_BOUNDARY \
    | SMMU_MSTR_RD_VA_OUT_OF_128BYTE \
    | SMMU_MSTR_RD_VA_OUT_OF_BOUNDARY)

#define SMMU_MSTR_INTCLR_ALL_UNMASK (0x00000000)
#define SMMU_MSTR_INTCLR_ALL_MASK (0x0000001f)
#define SMMU_MSTR_SMRX_0_LEN (0x00004000)
#define SMMU_MSTR_SMRX_START_ALL_STREAM (0x0000000f)
#define SMMU_INTCLR_S_PTW_NS_STAT (0x00000020)
#define SMMU_INTCLR_S_PTW_INVALID_STAT (0x00000010)
#define SMMU_INTCLR_S_PTW_TRANS_STAT (0x00000008)
#define SMMU_INTCLR_S_TLBMISS_STAT (0x00000004)
#define SMMU_INTCLR_S_EXT_STAT (0x00000002)
#define SMMU_INTCLR_S_PERMIS_STAT (0x00000001)
#define SMMU_COMMON_INTCLR_S_ALL_MASK (0x0000003f)
#define SMMU_COMMON_INTCLR_S_ALL (SMMU_INTCLR_S_PTW_NS_STAT \
    | SMMU_INTCLR_S_PTW_INVALID_STAT \
    | SMMU_INTCLR_S_PTW_TRANS_STAT \
    | SMMU_INTCLR_S_TLBMISS_STAT \
    | SMMU_INTCLR_S_EXT_STAT \
    | SMMU_INTCLR_S_PERMIS_STAT)
#define SMMU_CACHE_ALL_LEVEL_INVALID_LEVEL1 (0x00000003)
#define SMMU_CACHE_ALL_LEVEL_VALID_LEVEL1 (0x00000002)
#define SMMU_OPREF_CTRL_CONFIG_DUMMY (0x1)
#define SMMU_DEBUG_PORT_START1 (0x10000)
#define SMMU_DEBUG_PORT_START2 (0x20000)

#define NPU_SMMU_MSTR_DEBUG_PORT_NUM (32)
#define NPU_SMMU_MSTR_DEBUG_BASE_NUM (4)
#define NPU_SMMU_MSTR_DEBUG_AXI_RD_CMD_ADDR (0x10000)
#define NPU_SMMU_MSTR_DEBUG_AXI_RD_CMD_INFO (0x10100)
#define NPU_SMMU_MSTR_DEBUG_AXI_WR_CMD_ADDR (0x18000)
#define NPU_SMMU_MSTR_DEBUG_AXI_WR_CMD_INFO (0x18100)
#define NPU_SMMU_RD_CMD_BUF_BITMAP (0x10300)
#define NPU_SMMU_WR_CMD_BUF_BITMAP (0x18300)

#define SOC_SMMU_MSTR_BASE_ADDR_CORE0       (0xFF4A0000)
#define SOC_SMMU_MSTR_BASE_ADDR_CORE1       (0xe90a0000)
#define SOC_SMMU_COMM_BASE_ADDR_CORE0       (0xff480000)
#define SOC_SMMU_COMM_BASE_ADDR_CORE1       (0xe9080000)

/* SOC_SMMU_MSTR_GLB_BYPASS_UNION */
#define SOC_SMMU_MSTR_GLB_BYPASS_ADDR(base)           ((base) + (0x0000))

/* SOC_SMMU_MSTR_INPT_SEL_UNION */
#define SOC_SMMU_MSTR_INPT_SEL_ADDR(base)             ((base) + (0x0034))

/* SOC_SMMU_MSTR_INTCLR_UNION */
#define SOC_SMMU_MSTR_INTCLR_ADDR(base)               ((base) + (0x004C))

/* SOC_SMMU_MSTR_INTMASK_UNION */
#define SOC_SMMU_MSTR_INTMASK_ADDR(base)              ((base) + (0x0040))

/* SOC_SMMU_MSTR_INTSTAT_UNION */
#define SOC_SMMU_MSTR_INTSTAT_ADDR(base)              ((base) + (0x0048))

/* SOC_SMMU_MSTR_DBG_0_UNION */
#define SOC_SMMU_MSTR_DBG_0_ADDR(base)                ((base) + (0x0050))

/* SOC_SMMU_MSTR_DBG_1_UNION */
#define SOC_SMMU_MSTR_DBG_1_ADDR(base)                ((base) + (0x0054))

/* SOC_SMMU_MSTR_DBG_2_UNION */
#define SOC_SMMU_MSTR_DBG_2_ADDR(base)                ((base) + (0x0058))

/* SOC_SMMU_MSTR_DBG_3_UNION */
#define SOC_SMMU_MSTR_DBG_3_ADDR(base)                ((base) + (0x005C))

/* SOC_SMMU_MSTR_DBG_4_UNION */
#define SOC_SMMU_MSTR_DBG_4_ADDR(base)                ((base) + (0x0060))

/* SOC_SMMU_MSTR_DBG_5_UNION */
#define SOC_SMMU_MSTR_DBG_5_ADDR(base)                ((base) + (0x0064))

/* SOC_SMMU_MSTR_END_ACK_0_UNION */
#define SOC_SMMU_MSTR_END_ACK_0_ADDR(base)            ((base) + (0x001C))

/* SOC_SMMU_INTMAS_S_UNION */
#define SOC_SMMU_INTMAS_S_ADDR(base)                  ((base) + (0x0700))

/* SOC_SMMU_INTCLR_S_UNION */
#define SOC_SMMU_INTCLR_S_ADDR(base)                  ((base) + (0x070C))

/* SOC_SMMU_INTSTAT_S_UNION */
#define SOC_SMMU_INTSTAT_S_ADDR(base)                 ((base) + (0x0708))

/* SOC_SMMU_SCR_S_UNION */
#define SOC_SMMU_SCR_S_ADDR(base)                     ((base) + (0x0710))

/* SMMU Global Control Register for Protected Context Bank
   SOC_SMMU_SCR_P_UNION */
#define SOC_SMMU_SCR_P_ADDR(base)                     ((base) + (0x10210))

#define SOC_SMMU_SCR_ADDR(base)                       ((base) + (0x0000))
#define SOC_SMMU_INTCLR_NS_ADDR(base)                 ((base) + (0x001C))
#define SOC_SMMU_INTMASK_NS_ADDR(base)                ((base) + (0x0010))

struct smmu_manager {
    unsigned int master_io_addr[MAX_SUPPORT_CORE_NUM];
    unsigned int common_io_addr[MAX_SUPPORT_CORE_NUM];
    unsigned int smmu_port_select;
    unsigned int smmu_mstr_hardware_start;
    int stat_enable;
    struct smmu_irq_count irq_count;
    struct smmu_statistic smmu_stat[MAX_SUPPORT_CORE_NUM];
};

struct smmu_manager smmu_manager;

static void npu_smmu_mstr_init(unsigned int coreID)
{
    unsigned int io_mstr_base = smmu_manager.master_io_addr[coreID];

    //todo: check need ?
    /* set input signal as "register" by config SMMU_MSTR_INPT_SEL: 0(port) */
    if (smmu_manager.smmu_port_select) {
        writel(SMMU_MSTR_INPUT_SEL_REGISTER_DEFAULT, SOC_SMMU_MSTR_INPT_SEL_ADDR(io_mstr_base));
    }

    /* set SMMU-BYPASS mode, SMMU_MSTR_GLB_BYPASS.glb_bypass=0x1: bypass mode) */
    writel(SMMU_MSTR_GLB_BYPASS_DIRECTLY_MODE, SOC_SMMU_MSTR_GLB_BYPASS_ADDR(io_mstr_base));

    /* clean interrupt, and NOT mask all interrupts by config SMMU_MSTR_INTCLR and SMMU_MSTR_INTMASK */
    writel(SMMU_MSTR_INTCLR_ALL, SOC_SMMU_MSTR_INTCLR_ADDR(io_mstr_base));
    writel(SMMU_MSTR_INTCLR_ALL_UNMASK, SOC_SMMU_MSTR_INTMASK_ADDR(io_mstr_base));

    return;
}

static void npu_smmu_mstr_exit(unsigned int coreID)
{
    unsigned int io_mstr_base = smmu_manager.master_io_addr[coreID];

    /* set input signal as "register" by config SMMU_MSTR_INPT_SEL */
    if (smmu_manager.smmu_port_select) {
        writel(SMMU_MSTR_INPUT_SEL_REGISTER, SOC_SMMU_MSTR_INPT_SEL_ADDR(io_mstr_base));
    }

    /* clean interrupt, and NOT mask all interrupts by config SMMU_MSTR_INTCLR and SMMU_MSTR_INTMASK */
    writel(SMMU_MSTR_INTCLR_ALL, SOC_SMMU_MSTR_INTCLR_ADDR(io_mstr_base));
    writel(SMMU_MSTR_INTCLR_ALL_MASK, SOC_SMMU_MSTR_INTMASK_ADDR(io_mstr_base));

    return;
}

static void npu_smmu_comm_init(unsigned int coreID)
{
    unsigned int io_comm_base = smmu_manager.common_io_addr[coreID];

    npu_reg_bit_write_dword(SOC_SMMU_SCR_ADDR(io_comm_base), 0, 0, 0x1);

    /* set Global secure Configuration: SMMU_SCR_S.glb_nscfg = 2(Secure) */
    npu_reg_bit_write_dword(SOC_SMMU_SCR_S_ADDR(io_comm_base), 0, 1, 0x2);

    /* SMMU_SCR_S.glb_bypass_s = 1(bypass),default value, no need set */
    npu_reg_bit_write_dword(SOC_SMMU_SCR_S_ADDR(io_comm_base), 8, 8, 0x1);

    /* clear SMMU interrupt(SMMU_INTCLR_S): 0xFF */
    writel(SMMU_COMMON_INTCLR_S_ALL, SOC_SMMU_INTCLR_S_ADDR(io_comm_base));
    npu_reg_bit_write_dword(SOC_SMMU_INTMAS_S_ADDR(io_comm_base), 0, 5, 0);

    return;
}

static void npu_smmu_comm_exit(unsigned int coreID)
{
    unsigned int io_comm_base = smmu_manager.common_io_addr[coreID];

    /* SMMU_SCR_S.glb_bypass_s = 0(non-bypass) */
    npu_reg_bit_write_dword(SOC_SMMU_SCR_ADDR(io_comm_base), 0, 0, 0x1);

    /* set Global secure Configuration: SMMU_SCR_S.glb_nscfg = 3(no-Secure) */
    npu_reg_bit_write_dword(SOC_SMMU_SCR_S_ADDR(io_comm_base), 0, 1, 0x3);

    npu_reg_bit_write_dword(SOC_SMMU_SCR_S_ADDR(io_comm_base), 8, 8, 0x1);

    /* clear SMMU interrupt(SMMU_INTCLR_S) */
    writel(SMMU_COMMON_INTCLR_S_ALL, SOC_SMMU_INTCLR_S_ADDR(io_comm_base));

    /* clear MASK of interrupt(SMMU_INTMAS_S) */
    npu_reg_bit_write_dword(SOC_SMMU_INTMAS_S_ADDR(io_comm_base), 0, 5, 0x3F);

    return;
}

void npu_smmu_init(unsigned int coreID)
{
    npu_smmu_mstr_init(coreID);
    npu_smmu_comm_init(coreID);
    return;
}

void npu_smmu_exit(unsigned int coreID)
{
    npu_smmu_mstr_exit(coreID);
    npu_smmu_comm_exit(coreID);
    return;
}


int npu_smmu_mngr_init(void)
{
    int loop;
    unsigned int base_addr;
#ifdef VERSION_V150
    int core_number = 1;
#else
    int core_number = MAX_SUPPORT_CORE_NUM;
#endif

    memset_s(&smmu_manager, sizeof(smmu_manager), 0, sizeof(smmu_manager));

    for (loop = 0; loop < core_number; loop++) {
        base_addr = (0 == loop)?SOC_SMMU_MSTR_BASE_ADDR_CORE0:SOC_SMMU_MSTR_BASE_ADDR_CORE1;
        smmu_manager.master_io_addr[loop] = base_addr;

        base_addr = (0 == loop)?SOC_SMMU_COMM_BASE_ADDR_CORE0:SOC_SMMU_COMM_BASE_ADDR_CORE1;
        smmu_manager.common_io_addr[loop] = base_addr;
    }

    smmu_manager.smmu_port_select = 0;
    smmu_manager.smmu_mstr_hardware_start = 0;

    return 0;
}

void npu_smmu_mngr_exit(void)
{
    memset_s(&smmu_manager, sizeof(smmu_manager), 0, sizeof(smmu_manager));
    return;
}

void npu_smmu_set_stat_en(int enable)
{
    smmu_manager.stat_enable = enable;
    return;
}

int npu_smmu_get_stat_en(void)
{
    return smmu_manager.stat_enable;
}

bool npu_smmu_interrupt_handler(unsigned int coreID)
{
    unsigned int mstr_io_addr;
    unsigned int comm_io_addr;
    struct smmu_irq_count *irq_count = &smmu_manager.irq_count;
    unsigned int reg_smmu_mstr_status;
    unsigned int reg_smmu_comm_status;
    bool ret = false;

    mstr_io_addr = smmu_manager.master_io_addr[coreID];
    comm_io_addr = smmu_manager.common_io_addr[coreID];

    reg_smmu_comm_status = readl(SOC_SMMU_INTSTAT_S_ADDR(comm_io_addr));
    reg_smmu_mstr_status = readl(SOC_SMMU_MSTR_INTSTAT_ADDR(mstr_io_addr));

    if (0 != reg_smmu_mstr_status) {
        ret = true;
        NPU_ERR(" smmu mstr interrupt received: %x\n", reg_smmu_mstr_status);
        if (reg_smmu_mstr_status & SMMU_MSTR_WDATA_BURST) {
            irq_count->mstr_wdata_burst++;
        }
        if (reg_smmu_mstr_status & SMMU_MSTR_WR_VA_OUT_OF_128BYTE) {
            irq_count->mstr_wr_va_out_of_128byte++;
        }
        if (reg_smmu_mstr_status & SMMU_MSTR_WR_VA_OUT_OF_BOUNDARY) {
            irq_count->mstr_wr_va_out_of_boundary++;
        }
        if (reg_smmu_mstr_status & SMMU_MSTR_RD_VA_OUT_OF_128BYTE) {
            irq_count->mstr_rd_va_out_of_128byte++;
        }
        if (reg_smmu_mstr_status & SMMU_MSTR_RD_VA_OUT_OF_BOUNDARY) {
            irq_count->mstr_rd_va_out_of_boundary++;
        }

        NPU_DEBUG("Rd_Inst_SID=0x%pK, RdAddr=0x%pK, Wr_Inst_SID=0x%pK, WrAddr=0x%pK\n",
            readl(SOC_SMMU_MSTR_DBG_0_ADDR(mstr_io_addr)),
            readl(SOC_SMMU_MSTR_DBG_1_ADDR(mstr_io_addr)),
            readl(SOC_SMMU_MSTR_DBG_2_ADDR(mstr_io_addr)),
            readl(SOC_SMMU_MSTR_DBG_3_ADDR(mstr_io_addr)));

        NPU_DEBUG("RW_Burst_len=0x%pK, Awaddr=0x%pK\n",
            readl(SOC_SMMU_MSTR_DBG_4_ADDR(mstr_io_addr)),
            readl(SOC_SMMU_MSTR_DBG_5_ADDR(mstr_io_addr)));

        /* clear smmu mstr interrupt */
        writel(SMMU_MSTR_INTCLR_ALL, SOC_SMMU_MSTR_INTCLR_ADDR(mstr_io_addr));
    }

    if (0 != reg_smmu_comm_status) {
        ret = true;
        NPU_ERR(" smmu common interrupt received: 0x%x\n", reg_smmu_comm_status);

        if (reg_smmu_comm_status & SMMU_INTCLR_S_PTW_NS_STAT) {
            /* When PTW transaction receive an page table whose ns bit is not match to the prefetch
            transaction, occur this fault. */
            irq_count->comm_ptw_ns_stat++;
        }
        if (reg_smmu_comm_status & SMMU_INTCLR_S_PTW_INVALID_STAT) {
            /* When PTW transaction receive an invalid page table descriptor or access the invalid
            regoin between t0sz and t1sz in long descriptor mode, occur this fault.*/
            irq_count->comm_ptw_invalid_stat++;
        }
        if (reg_smmu_comm_status & SMMU_INTCLR_S_PTW_TRANS_STAT) {
            /* When PTW transaciont receive an error response, occur this fault. */
            irq_count->comm_ptw_trans_stat++;
        }
        if (reg_smmu_comm_status & SMMU_INTCLR_S_TLBMISS_STAT) {
            /* When there is a TLB miss generated during the translation process, the mmu will record this. */
            irq_count->comm_tlbmiss_stat++;
        }
        if (reg_smmu_comm_status & SMMU_INTCLR_S_EXT_STAT) {
            /* When mmu receive an en error response the mmu will record this as a fault. */
            irq_count->comm_ext_stat++;
        }
        if (reg_smmu_comm_status & SMMU_INTCLR_S_PERMIS_STAT) {
            /* When the input transaction¡¯s attributes doesn¡¯t match the attributes descripted in the page table,
            the mmu will raise a fault for this. */
            irq_count->comm_permis_stat++;
        }

        /* clear smmu interrupt */
        writel(SMMU_COMMON_INTCLR_S_ALL, SOC_SMMU_MSTR_END_ACK_0_ADDR(comm_io_addr));
    }

    return ret;
}

