#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"

#include <sre_typedef.h>
#include <sre_sys.h>
#include <sre_hwi.h>
#include <tee_defines.h>
#include <mem_ops.h>
#include <drv_module.h>
#include <drv_cache_flush.h> /* v7_dma_flush_range */
#include <register_ops.h> /* readl */
#include <drv_pal.h> /* task_caller */

#include <sys/hmapi_ext.h>

#include "stdint.h"
#include "libhwsecurec/securec.h"
#include "pthread.h"
#include "npu_public_sec.h"
#include "npu_main_sec.h"
#include "npu_task_sec.h"
#include "npu_smmu_sec.h"

#define NPU_WAIT_THRESHOLD_US (100)

#define SOC_ICS_SOFT_RST_REQ_ADDR(base)               ((base) + (0x0074))

#define SOC_ICS_SOFT_RST_ACK_ADDR(base)               ((base) + (0x0078))

#define SOC_PMCTRL_NOC_POWER_IDLEREQ_0_ADDR(base)     ((base) + (0x380))

#define SOC_PMCTRL_NOC_POWER_IDLEACK_0_ADDR(base)     ((base) + (0x384))

#define SOC_PMCTRL_NOC_POWER_IDLE_0_ADDR(base)        ((base) + (0x388))

#define SOC_PCTRL_PERI_STAT3_ADDR(base)               ((base) + (0x0A0))

#define SOC_MEDIA2_CRG_PERDIS0_ADDR(base)             ((base) + (0x004))

#define SOC_MEDIA2_CRG_PERRSTEN0_ADDR(base)           ((base) + (0x030))

#define SOC_MEDIA2_CRG_PEREN0_ADDR(base)              ((base) + (0x000))

#define SOC_CRGPERIPH_CLKDIV18_ADDR(base)             ((base) + (0x0F0))

#define SOC_MEDIA2_CRG_PERRSTDIS0_ADDR(base)          ((base) + (0x034))

#define SOC_MEDIA1_CRG_PEREN0_ADDR(base)              ((base) + (0x000))

#define SOC_MEDIA1_CRG_PERDIS0_ADDR(base)             ((base) + (0x004))

#define SOC_MEDIA1_CRG_PERRSTEN0_ADDR(base)           ((base) + (0x030))

#define SOC_MEDIA1_CRG_CLKDIV15_ADDR(base)            ((base) + (0x09C))

#define SOC_MEDIA1_CRG_PERRSTDIS0_ADDR(base)          ((base) + (0x034))


#define NPU_DCQ_DMSS_MSTS (0x9)
#define SOC_ICS_IRQ_BASE_ADDR_CORE0       (0xFF4A2000)
#define SOC_ICS_IRQ_BASE_ADDR_CORE1       (0xE90A2000)

#define NPU_DMA_IRQ_CORE0       (327)
//todo: confirm irq number  #define NPU_DMA_IRQ_CORE1       (404)

/* ICS secure interrupt mask register.
   SOC_ICS_IRQ_MASK_S_UNION */
#define SOC_ICS_IRQ_MASK_S_ADDR(base)                 ((base) + (0x0010))

/* ICS secure interrupt clear register.
   SOC_ICS_IRQ_CLR_S_UNION */
#define SOC_ICS_IRQ_CLR_S_ADDR(base)                  ((base) + (0x001C))

#define SOC_ACPU_PMC_BASE_ADDR                        (0xFFF31000)

#define SOC_ACPU_PCTRL_BASE_ADDR                      (0xE8A09000)

#define SOC_ACPU_MEDIA2_CRG_BASE_ADDR                 (0xE8900000)

#define SOC_ACPU_MEDIA1_CRG_BASE_ADDR                 (0xE87FF000)

#define SOC_ACPU_PERI_CRG_BASE_ADDR                   (0xFFF35000)

#define SOC_ACPU_DMSS_BASE_ADDR                       (0xEA980000)

/*  SOC_DMSS_GLB_MST_FLUX_UNION */
#define SOC_DMSS_GLB_MST_FLUX_ADDR(base, dcq_msts)    ((base) + (0x6280+0x4*(dcq_msts)))

#define SOC_TZPC_DECPROT_BASE_ADDR       (0xE8A21000)

/* SOC_TZPC_DECPROT8STAT_UNION */
#define SOC_TZPC_DECPROT8STAT_ADDR(base)              ((base) + (0x860))

#define SEC_MODE_OPENFD                 (0X45464153)

#define        _IOC_NRBITS          8
#define        _IOC_TYPEBITS        8
#define        _IOC_SIZEBITS       14
#define        _IOC_DIRBITS         2
#define        _IOC_NRMASK       ((1 << _IOC_NRBITS)-1)
#define        _IOC_TYPEMASK     ((1 << _IOC_TYPEBITS)-1)
#define        _IOC_SIZEMASK     ((1 << _IOC_SIZEBITS)-1)
#define        _IOC_DIRMASK      ((1 << _IOC_DIRBITS)-1)
#define        _IOC_NRSHIFT       0
#define        _IOC_TYPESHIFT    (_IOC_NRSHIFT+_IOC_NRBITS)
#define        _IOC_SIZESHIFT    (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define        _IOC_DIRSHIFT     (_IOC_SIZESHIFT+_IOC_SIZEBITS)
#define        _IOC_TYPE(nr)   (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define        _IOC_NR(nr)     (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_NONE     0U
#define _IOC_WRITE    1U
#define _IOC_READ     2U
#define _IOC(dir, type, nr, size) \
       (((dir)  << _IOC_DIRSHIFT) | \
        ((type) << _IOC_TYPESHIFT) | \
        ((nr)   << _IOC_NRSHIFT) | \
        ((size) << _IOC_SIZESHIFT))

#define _IO(type,nr)          _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)    _IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW(type,nr,size)    _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR(type,nr,size)   _IOC(_IOC_READ|_IOC_WRITE,(type),(nr), sizeof(size))

#define MAGIC_NUM (100)
#define RDCONFIG_DWORD             _IOR(MAGIC_NUM, 12, unsigned int[2])
#define WRCONFIG_DWORD             _IOW(MAGIC_NUM, 13, unsigned int[3])
#define IN_TASKQUEUE               _IOW(MAGIC_NUM, 14, unsigned int[11])
#define GETCONFIG_CHIP_TYPE        _IOR(MAGIC_NUM, 15, unsigned int[2])
#define SET_SECURE_MODE            _IOR(MAGIC_NUM, 35, int[2])
#define RELEASE_SECURE_MODE        _IOR(MAGIC_NUM, 36, int[2])

#define FLUSH_DMA_ADDRESS          _IOR(MAGIC_NUM, 40, unsigned int[2])

#define NPU_IOC_MAXNR   (64)

typedef int (*ioctl_cb)(unsigned int *);

/* IOCTL map */
struct npu_ioctl_map {
    unsigned int cmd;
    ioctl_cb func;
};

typedef struct {
    int fd;
    unsigned int cmd;
    unsigned int *param;
} npu_ops_ioctl_info;

typedef struct {
    int fd;
}npu_ops_release_info;

typedef struct {
    int fd;
    const char *buf;
    unsigned int count;
    int *f_pos;
}npu_ops_write_info;

/*whence 0 SEEK_SET 1 SEEK_CUR 2 SEEK_END*/
typedef struct {
    int fd;
    int off;
    int whence;
}npu_ops_llseek_info;

NPU_MAIN_PRIVATE_S adapter;

static bool npu_chip_can_direct_access(unsigned int coreid)
{
    if (SECURETY == adapter.core[coreid].security_mode) {
        return true;
    }

    return false;
}

/* npu char device ops function implementation, inode:node of file, filp: pointer of file */
static int npu_open_sec(void)
{
    int coreid = 0;

    for (coreid = 0; coreid < (int)(adapter.common.feature.core_num); coreid++) {
        CTRL_LOCK(coreid);
    }

    if (adapter.common.npu_opened) {

        NPU_DEBUG("NPU device has already opened !\n");
        for (coreid = (int)(adapter.common.feature.core_num - 1); coreid >= 0; coreid--) {
            CTRL_UNLOCK(coreid);
        }

        return -1;
    }

    npu_smmu_set_stat_en(0);

    adapter.common.npu_opened = true;

    for (coreid = (int)(adapter.common.feature.core_num - 1); coreid >= 0; coreid--) {
        CTRL_UNLOCK(coreid);
    }

    NPU_DEBUG("NPU device open success!\n");
    return SEC_MODE_OPENFD;
}

/* npu device release and power down */
static int npu_release_sec(int fd)
{
    int coreid = 0;

    if ( SEC_MODE_OPENFD != fd )
    {
        NPU_ERR("input err fd:0x%x\n", fd);
        return -1;
    }

    for (coreid = 0; coreid < (int)(adapter.common.feature.core_num); coreid++) {
        CTRL_LOCK(coreid);
    }

    if (!adapter.common.npu_opened) {

        NPU_DEBUG("npu device is already closed\n");
        for (coreid = (int)(adapter.common.feature.core_num - 1); coreid >= 0; coreid--) {
            CTRL_UNLOCK(coreid);
        }

        return -1;
    }

    adapter.common.npu_opened = false;

    for (coreid = (int)(adapter.common.feature.core_num - 1); coreid >= 0; coreid--) {
        CTRL_UNLOCK(coreid);
    }

    NPU_DEBUG("NPU device release success!\n");
    return 0;
}

/* CPU write inst to NPU SRAM */
static int npu_write_sec(int fd, const char *buf, unsigned int count, int *f_pos)
{
    int ret_value = 0;
    int file_pos = 0;
    unsigned int coreid = 0;

    if ( SEC_MODE_OPENFD != fd )
    {
        NPU_ERR("input err fd:0x%x\n", fd);
        return -1;
    }

    if ((!buf) || (!f_pos)) {
        NPU_ERR("input parameter inode or filp is invalid !\n");
        return 0;
    }

    if (count == 0) {
        NPU_ERR("param err count[%ld]!", count);
        return 0;
    }

#ifdef VERSION_V150
    coreid   = 0;
    file_pos = *f_pos;
#else
    file_pos = *f_pos;
    coreid = (file_pos & 0xF0000) >> 16;
    file_pos &= 0xFFFF;
#endif

    NPU_DEBUG("coreid = %d!\n", coreid);

    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("coreid [%d] err\n", coreid);
        return 0;
    }

    CTRL_LOCK(coreid);

    #ifdef VERSION_V150
        ret_value = npu_task_write_inst(coreid, buf, count, file_pos);
    #else
    if (npu_chip_can_direct_access(coreid)) {
        ret_value = npu_task_write_inst(coreid, buf, count, file_pos);
    }
    #endif

    CTRL_UNLOCK(coreid);
    NPU_DEBUG("write %d bytes", ret_value);
    return ret_value;
}

static int npu_llseek_sec(int fd, int off, int whence)
{
    unsigned int coreid = 0;
    int pos;

    if ( SEC_MODE_OPENFD != fd )
    {
        NPU_ERR("input err fd:0x%x\n", fd);
        return -1;
    }

    CTRL_LOCK(0);

    pos = npu_task_llseek_proc(coreid, 0, off, whence);

    CTRL_UNLOCK(0);

    NPU_DEBUG("llseek ret pos: %d ", pos);
    return pos;
}

static int npu_read_dword(unsigned int *param)
{
    int read_value;
    unsigned int coreid = 0;
    unsigned int offset = 0;

    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

    coreid = param[0];
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return -1;
    }

    CTRL_LOCK(coreid);
    if (!npu_chip_can_direct_access(coreid)) {
        CTRL_UNLOCK(coreid);
        NPU_ERR("this work is not allowed when NPU[%d] is work-off, FATAL and ignore\n", coreid);
        return -1;
    }

    offset = param[1];
    read_value = npu_task_read_dword(coreid, offset);
    CTRL_UNLOCK(coreid);
    NPU_DEBUG("Read NPU 0x%x CONFIG REG dword offset 0x%pK, value is 0x%x", coreid, (void*)param[1], read_value);

    return read_value;
}

static int __attribute__((unused)) npu_can_write(unsigned int coreid, int offset, int data)
{
    if ((NPU_START_REG == offset) || (NPU_STATUS_REG == offset) || (NPU_BASE_ADDR_REG == offset)) {
        npu_task_write_dword(coreid, offset, data);
    } else {
        NPU_ERR("error offset when npu on, offset=%d, data=%d\n", offset, data);
        return -1;
    }

    return 0;
}
static int npu_write_dword(unsigned int *param)
{
    unsigned int coreid = 0;
    unsigned int offset = 0;
    unsigned int value = 0;

    int ret = 0;

    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

    coreid = param[0];
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return -1;
    }

    offset = param[1];
    value  = param[2];

    NPU_DEBUG("Write NPU %d CONFIG REG dword offset 0x%pk, value is 0x%x", coreid, offset, value);

    CTRL_LOCK(coreid);

#ifdef VERSION_V150
    if (npu_chip_can_direct_access(coreid)) {
        /*save base addr not matter power is on*/
        if (NPU_BASE_ADDR_REG == offset) {
            npu_task_set_boot_inst(coreid, true, value);
        }

        ret = npu_can_write(coreid, offset, value);
        if (ret) {
            NPU_ERR("error offset when ipu on, offset=0x%pk, data=0x%x\n", offset, value);
            goto exit;
        }
    } else {
        if (NPU_BASE_ADDR_REG == offset) {
            npu_task_set_boot_inst(coreid, true, value);
        }
        else {
            NPU_ERR("error offset when npu off, offset=0x%pk, data=0x%x\n", offset, value);
            goto exit;
        }
    }
#else
    if (!npu_chip_can_direct_access(coreid)) {
        NPU_ERR("this work is not allowed when NPU[%d] is work-off, FATAL and ignore\n", coreid);
        ret = -1;
        goto exit;
    }
    npu_task_write_dword(coreid, offset, value);

#endif

exit:

    CTRL_UNLOCK(coreid);
    return ret;
}

/*this func is special common lock put task module*/
static int npu_process_workqueue(unsigned int *param)
{
    int ret = 0;
    unsigned int coreid;

    if (!param) {
        NPU_ERR("Input parameter arg is NULL, FATAL arg and ignore!");
        return -1;
    }

    coreid = param[0];
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return -1;
    }

    /*this func is special common lock put task module*/
    ret = npu_push_task((void *)param, adapter.core[coreid].irq);
    if (ret) {
        NPU_ERR("Call npu_push_task failed! ret=%d\n", ret);
        return -1;
    }

    return 0;
}

/*get chip num*/
static int npu_get_chip_type(unsigned int *param)
{
    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

#ifdef VERSION_V150
    param[0] = NPU_VERSION_V150;
#else
    param[0] = NPU_VERSION_V200;
#endif

    param[1] = PLATFORM_VERSION;

    NPU_DEBUG("param[0][0x%x], param[1][0x%x] \n", param[0], param[1]);

    //todo: need modify to 0
    return 1;
}

void npu_reg_bit_write_dword
(
    unsigned int reg_addr,
    unsigned int start_bit,
    unsigned int end_bit,
    unsigned int content
)
{
    unsigned int set_value;
    unsigned int reg_content;
    unsigned int tmp_mask;
    unsigned int tmp_bit;

    if ((end_bit < start_bit)
        || (start_bit > 31)
        || (end_bit > 31)) {
        NPU_ERR(" error input: reg_addr=%pK,start_bit=0x%x,end_bit=0x%x,content=0x%x\n",
            (void *)reg_addr, start_bit, end_bit, content);
        return;
    }
    set_value      = content;
    set_value      = set_value << start_bit;

    tmp_bit        = 31 - end_bit;
    tmp_mask       = 0xffffffff << tmp_bit;
    tmp_mask       = tmp_mask >> ( start_bit + tmp_bit);
    tmp_mask       = tmp_mask << start_bit;

    reg_content    = (unsigned int)readl(reg_addr);
    reg_content   &= (~tmp_mask);
    set_value     &= tmp_mask;
    writel((reg_content | set_value), reg_addr);
    return;
}

/*interrupt init*/
static void npu_interrupt_init(unsigned int coreid)
{
    unsigned int irq_io_addr = adapter.core[coreid].npu_irq.io_addr;

    /* clear npu status to unfinished */
    npu_task_finish_interrupt_clear(coreid);

    /* clear s interrupt, ICS_IRQ_CLR_S */
    writel(NPU_IRQ_CLEAR_IRQ_S, SOC_ICS_IRQ_CLR_S_ADDR(irq_io_addr));

    /* unmask interrupt */
    writel(NPU_IRQ_UNMASK_SECURITY, SOC_ICS_IRQ_MASK_S_ADDR(irq_io_addr));

    return;
}

/* to mask npu interrupt and will not receive it */
static void npu_interrupt_deinit(unsigned int coreid)
{
    unsigned int irq_io_addr = adapter.core[coreid].npu_irq.io_addr;

    /* clear npu status to unfinished */
    npu_task_finish_interrupt_clear(coreid);

    /* clear ns interrupt */
    writel(NPU_IRQ_CLEAR_IRQ_S, SOC_ICS_IRQ_CLR_S_ADDR(irq_io_addr));

    /* mask interrupt */
    writel(NPU_IRQ_MASK_SECURITY, SOC_ICS_IRQ_MASK_S_ADDR(irq_io_addr));

    return;
}

static void npu_set_npu_tosafemode(unsigned int coreid)
{
#ifdef VERSION_V150
    /* donothing */
#else
    if (0 == coreid) {
        npu_reg_bit_write_dword(SOC_TZPC_DECPROT8STAT_ADDR(SOC_TZPC_DECPROT_BASE_ADDR), 10, 10, 0x0);
    } else {
        npu_reg_bit_write_dword(SOC_TZPC_DECPROT8STAT_ADDR(SOC_TZPC_DECPROT_BASE_ADDR), 16, 16, 0x0);
    }
#endif

    return;
}

static void npu_set_npu_tonormalmode(unsigned int coreid)
{
#ifdef VERSION_V150
    /* donothing */
#else
    if (0 == coreid) {
        npu_reg_bit_write_dword(SOC_TZPC_DECPROT8STAT_ADDR(SOC_TZPC_DECPROT_BASE_ADDR), 10, 10, 0x1);
    } else {
        npu_reg_bit_write_dword(SOC_TZPC_DECPROT8STAT_ADDR(SOC_TZPC_DECPROT_BASE_ADDR), 16, 16, 0x1);
    }
#endif

    return;
}

/*soft reset*/
static void npu_soft_reset(unsigned int coreid)
{
    int loop = 0;
    unsigned long irq_io_addr = (unsigned long)adapter.core[coreid].npu_irq.io_addr;

    /*config ICS_SOFT_RST_REQ  = 0x1*/
    writel(1, SOC_ICS_SOFT_RST_REQ_ADDR(irq_io_addr));

    /* loop wait ICS_SOFT_RST_ACK == 0x1 */
    for (loop = 0; loop < NPU_WAIT_THRESHOLD_US; loop++) {
        if (SOFT_RST_ACK == readl(SOC_ICS_SOFT_RST_ACK_ADDR(irq_io_addr))) {
            break;
        }

        //SRE_DelayMs(1);
        hmapi_yield();
    }

    if (NPU_WAIT_THRESHOLD_US == loop) {
        NPU_ERR("FATAL error: no response of SOFT reset\n");
    } else {
        NPU_DEBUG("loop wait ICS_SOFT_RST_ACK ok\n");
    }

    return;
}

/*wait noc to idle*/
static void wait_noc_idle(unsigned int coreid)
{
    unsigned int loop_cnt = 0;
    int noc_idle = 0;
    int noc_power_idle_ack;
    int noc_power_idle_stat;
    int noc_peri_status;

    unsigned long pctrl_io_addr  = (unsigned long)adapter.common.pctrl_reg.io_addr;
    unsigned long pmctrl_io_addr = (unsigned long)adapter.common.pmctrl_reg.io_addr;

    /*waiting for Ics_noc_bus to enter idle state*/
    while (!noc_idle) {
        if (loop_cnt > NPU_WAIT_THRESHOLD_US) {
            NPU_ERR("FATAL: loop timeout\n");
            break;
        }

        if (0 == coreid) {
            /* read Pmctrl registers noc_power_idleack_0 bit[9]*/
            noc_power_idle_ack = readl(SOC_PMCTRL_NOC_POWER_IDLEACK_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLEACK_0_BIT9;

            /* read Pmctrl register noc_power_idle_0 bit[9] */
            noc_power_idle_stat = readl(SOC_PMCTRL_NOC_POWER_IDLE_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLE_0_BIT9;

            /* read Pctrl register PERI_STAT3 bit[22] */
            noc_peri_status = readl(SOC_PCTRL_PERI_STAT3_ADDR(pctrl_io_addr)) & CONFIG_PCTRL_PERI_STAT3_BIT22;
        } else {
            /* read Pmctrl registers noc_power_idleack_0 bit[12]*/
            noc_power_idle_ack = readl(SOC_PMCTRL_NOC_POWER_IDLEACK_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLEACK_0_BIT12;

            /* read Pmctrl register noc_power_idle_0 bit[12] */
            noc_power_idle_stat = readl(SOC_PMCTRL_NOC_POWER_IDLE_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLE_0_BIT12;

            /* read Pctrl register PERI_STAT3 bit[23] */
            noc_peri_status = readl(SOC_PCTRL_PERI_STAT3_ADDR(pctrl_io_addr)) & CONFIG_PCTRL_PERI_STAT3_BIT23;
        }

        noc_idle = noc_power_idle_ack && noc_power_idle_stat && noc_peri_status;

        NPU_DEBUG("noc_power_idle_ack:0x%x, noc_power_idle_stat:0x%x, noc_peri_status:0x%x\n",
                noc_power_idle_ack, noc_power_idle_stat, noc_peri_status);

        //SRE_DelayMs(1);
        hmapi_yield();

        loop_cnt++;
    }

    return;
}

/*reset func*/
void npu_reset_proc(unsigned int coreid)
{
    unsigned int pmctrl_data = 0;
    int noc_power_idle_ack;
    int noc_power_idle_stat;
    NPU_MAIN_PRIVATE_COMMON_S* p_common = &adapter.common;
    unsigned long media2_io_addr = (unsigned long)p_common->media2_reg.io_addr;
    unsigned long media1_io_addr = (unsigned long)p_common->media1_reg.io_addr;
    unsigned long pmctrl_io_addr = (unsigned long)p_common->pmctrl_reg.io_addr;
    unsigned long peri_io_addr   = (unsigned long)p_common->peri_reg.io_addr;

    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return;
    }

    if ( (p_common->feature.npu_reset_when_in_error != RESET_BY_CONFIG_NOC_BUS)
        && (p_common->feature.npu_reset_when_in_error != SOFT_RESET) ) {
        NPU_ERR("unsupported npu reset trategy=%u!\n",
                p_common->feature.npu_reset_when_in_error);
        return;
    }

    /*1. soft reset*/
    if (SOFT_RESET == p_common->feature.npu_reset_when_in_error) {
        npu_soft_reset(coreid);

        NPU_DEBUG("core[%d] wait SOFT_RST_ACK ok\n", coreid);
    } else {
        /* donothing */
    }

    if (0 == coreid) {
        pmctrl_data = NOC_POWER_IDLEREQ_0;
    } else {
        pmctrl_data = NOC_POWER_IDLEREQ_1;
    }

    /*2. config PMCTRL NOC_POWER_IDLEREQ_0 */
    writel(pmctrl_data, SOC_PMCTRL_NOC_POWER_IDLEREQ_0_ADDR(pmctrl_io_addr));

    /*3. wait ICS_NOC_BUS to idle*/
    wait_noc_idle(coreid);

    if (0 == coreid) {
        /*4. module rst */
        writel(CONFIG_MEDIA2_REG_PERDIS0, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));
#ifndef VERSION_V150
        writel(CONFIG_MEDIA2_REG_PERRSTEN0_V200, SOC_MEDIA2_CRG_PERRSTEN0_ADDR(media2_io_addr));
#else
        writel(CONFIG_MEDIA2_REG_PERRSTEN0_V150, SOC_MEDIA2_CRG_PERRSTEN0_ADDR(media2_io_addr));
#endif

        writel(CONFIG_MEDIA2_REG_PEREN0, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));

        /*5. module clk disable*/
        writel(CONFIG_MEDIA2_REG_PERDIS0, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));
        writel(CONFIG_SC_GT_CLK_NPU_DIS, SOC_CRGPERIPH_CLKDIV18_ADDR(peri_io_addr));

        /*6. reset*/
        writel(CONFIG_SC_GT_CLK_NPU_EN, SOC_CRGPERIPH_CLKDIV18_ADDR(peri_io_addr));
        writel(CONFIG_MEDIA2_REG_PEREN0, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));
        writel(CONFIG_MEDIA2_REG_PERDIS0, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));

#ifndef VERSION_V150
        writel(CONFIG_MEDIA2_REG_PERRSTDIS0_V200, SOC_MEDIA2_CRG_PERRSTDIS0_ADDR(media2_io_addr));
#else
        writel(CONFIG_MEDIA2_REG_PERRSTDIS0_V150, SOC_MEDIA2_CRG_PERRSTDIS0_ADDR(media2_io_addr));
#endif
        writel(CONFIG_MEDIA2_REG_PEREN0, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));

        /*7. bus idle clear */
        writel(CONFIG_NOC_NPU_POWER_IDLEREQ_DIS_0, SOC_PMCTRL_NOC_POWER_IDLEREQ_0_ADDR(pmctrl_io_addr));
        noc_power_idle_ack = readl(SOC_PMCTRL_NOC_POWER_IDLEACK_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLEACK_0_BIT9;
        noc_power_idle_stat = readl(SOC_PMCTRL_NOC_POWER_IDLE_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLE_0_BIT9;
    } else {
        /* module rst */
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PERDIS0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));
        writel(CONFIG_MEDIA1_REG_IP_RESETBIT, SOC_MEDIA1_CRG_PERRSTEN0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_IP_RESETNOC, SOC_MEDIA2_CRG_PERRSTEN0_ADDR(media2_io_addr));
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PEREN0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));

        /* module clk disable */
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PERDIS0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));
        writel(CONFIG_MEDIA1_REG_CLKDIV15_DISABLE, SOC_MEDIA1_CRG_CLKDIV15_ADDR(media1_io_addr));

        /* module clk enable */
        writel(CONFIG_MEDIA1_REG_CLKDIV15_ENABLE, SOC_MEDIA1_CRG_CLKDIV15_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PEREN0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));

        /* module clk disable */
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PERDIS0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PERDIS0_ADDR(media2_io_addr));

        /* module unrst */
        writel(CONFIG_MEDIA1_REG_IP_RESETBIT, SOC_MEDIA1_CRG_PERRSTDIS0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_IP_RESETNOC, SOC_MEDIA2_CRG_PERRSTDIS0_ADDR(media2_io_addr));

        /* module clk enable */
        writel(CONFIG_MEDIA1_REG_GT_CLK_RET, SOC_MEDIA1_CRG_PEREN0_ADDR(media1_io_addr));
        writel(CONFIG_MEDIA2_REG_GT_CLK_NOC, SOC_MEDIA2_CRG_PEREN0_ADDR(media2_io_addr));

        /* bus idle clear */
        writel(CONFIG_NOC_NPU_POWER_IDLEREQ_DIS_1, SOC_PMCTRL_NOC_POWER_IDLEREQ_0_ADDR(pmctrl_io_addr));
        noc_power_idle_ack = readl(SOC_PMCTRL_NOC_POWER_IDLEACK_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLEACK_0_BIT12;
        noc_power_idle_stat = readl(SOC_PMCTRL_NOC_POWER_IDLE_0_ADDR(pmctrl_io_addr)) & CONFIG_NOC_POWER_IDLE_0_BIT12;
    }

    NPU_DEBUG("noc_power_idle_ack:%d, noc_power_idle_stat:%d\n", noc_power_idle_ack, noc_power_idle_stat);

    /* smmu init*/
    npu_smmu_init(coreid);

    /* interrupt init*/
    npu_interrupt_init(coreid);

    UNUSED_PARAMETER(noc_power_idle_ack);
    UNUSED_PARAMETER(noc_power_idle_stat);

    return;
}

void npu_reset(unsigned int coreid)
{
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return;
    }

    if (!npu_chip_can_direct_access(coreid)) {
        NPU_ERR(" npu_chip_can_direct_access is false\n");
        return;
    }

    /* reset ipu */
    npu_reset_proc(coreid);

    return;
}

static int npu_set_secure_mode(unsigned int *param)
{
    unsigned int coreid = 0;

    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

    coreid = param[0];
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("coreid[%d] err\n", coreid);
        return -1;
    }

    /* 1. undo mode lock*/
    MODE_UNLOCK(coreid);
    CTRL_LOCK(coreid);

    /* 2. set npu to security mode TZPC reg,  need first config */
    npu_set_npu_tosafemode(coreid);

    /* 3. set smmu to bypass mode */
    npu_smmu_init(coreid);

    /* 4. unmask safe interrupt and wait interrupt */
    npu_interrupt_init(coreid);

    /* 5. enter sec flag */
    adapter.core[coreid].security_mode = SECURETY;

    npu_task_restore(coreid);

    CTRL_UNLOCK(coreid);

    SRE_HwiEnable(adapter.core[coreid].irq);

    return 0;
}

static int npu_release_secure_mode(unsigned int *param)
{
    unsigned int coreid = 0;

    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

    coreid = param[0];
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("coreid[%d] err\n", coreid);
        return -1;
    }

    CTRL_LOCK(coreid);

    npu_reset_proc(coreid);

    /*1. mask safe interrupt, then no interrupt */
    npu_interrupt_deinit(coreid);

    /*2. set smmu normal state */
    npu_smmu_exit(coreid);

    /*3. set npu to normal mode */
    npu_set_npu_tonormalmode(coreid);

    /*4. enter sec flag */
    adapter.core[coreid].security_mode = NON_SECURETY;

    /* 5. mode lock */
    CTRL_UNLOCK(coreid);
    MODE_LOCK(coreid);

    SRE_HwiDisable(adapter.core[coreid].irq);

    return 0;
}

extern void v7_dma_flush_range(unsigned long start, unsigned long end);

static int npu_flush_dma_address(unsigned int *param)
{
    unsigned long start = 0;
    unsigned long end   = 0;

    if (!param) {
        NPU_ERR("input parameter arg is NULL, FATAL arg and ignore\n");
        return -1;
    }

    /*check value*/
    start = param[0];
    end   = start + param[1];

    NPU_DEBUG("start:0x%x, end:0x%x, size:0x%x\n", start, end, param[1]);
    v7_dma_flush_range(start, end);

    return 0;
}
static const struct npu_ioctl_map npu_ioctl_maps[] = {
    {RDCONFIG_DWORD,            npu_read_dword},
    {WRCONFIG_DWORD,            npu_write_dword},
    {GETCONFIG_CHIP_TYPE,       npu_get_chip_type},
    {IN_TASKQUEUE,              npu_process_workqueue},
    {SET_SECURE_MODE,           npu_set_secure_mode},
    {RELEASE_SECURE_MODE,       npu_release_secure_mode},
    {FLUSH_DMA_ADDRESS,         npu_flush_dma_address},
};

static int npu_input_filp_check(int fd, unsigned int cmd)
{
    if ( SEC_MODE_OPENFD != fd )
    {
        NPU_ERR("input err fd:0x%x\n", fd);
        return -1;
    }

    /* check whether cmd is valid */
    if (_IOC_TYPE(cmd) != MAGIC_NUM) {
        NPU_ERR("cmd is invalid!(not a MAGIC_NUM)\n");
        return -1;
    }

    if (_IOC_NR(cmd) > NPU_IOC_MAXNR) {
        NPU_ERR("cmd is invalid!(%d > IPU_IOC_MAXNR)\n", _IOC_NR(cmd));
        return -1;
    }

    NPU_DEBUG("cmd is (%d)\n", _IOC_NR(cmd));
    return 0;
}

static ioctl_cb npu_obtain_ioctl_callback(unsigned int cmd)
{
    unsigned int cnt;
    unsigned int size = sizeof(npu_ioctl_maps) / sizeof(npu_ioctl_maps[0]);

    for (cnt = 0; cnt < size; cnt++) {
        if (npu_ioctl_maps[cnt].cmd == cmd) {
            return npu_ioctl_maps[cnt].func;
        }
    }

    NPU_DEBUG("error cmd=0x%x\n", cmd);

    return NULL;
}

static int npu_ioctl(int fd, unsigned int cmd, unsigned int *param)
{
    ioctl_cb ioctl_callback;
    int ret = -1;

    if (npu_input_filp_check(fd, cmd)) {
        NPU_ERR(" input fd is invalid !\n");
        return -1;
    }

    if (!param) {
        NPU_ERR(" input param is NULL, FATAL arg and ignore\n");
        return -1;
    }

    ioctl_callback = npu_obtain_ioctl_callback(cmd);

    if (ioctl_callback) {
        ret = ioctl_callback(param);
    } else {
        NPU_ERR(" unknown cmd = 0x%x\n", _IOC_NR(cmd));
    }

    NPU_PRINT("cmd is (%d)\n", _IOC_NR(cmd));

    return ret;
}

unsigned int npu_syscall_ioctl_cmdproc(npu_ops_ioctl_info *command_info)
{
    int ret = 0;

    if (!command_info) {
        NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
        return -1;
    }

    NPU_DEBUG(" syscall ioctl Enter:fd:%d, cmd=%d \n",command_info->fd,_IOC_NR(command_info->cmd));

    ret = npu_ioctl(command_info->fd, command_info->cmd, command_info->param);

    return ret;
}

unsigned int npu_syscall_open_cmdproc(void)
{
    int ret = 0;

    NPU_DEBUG(" syscall open Enter \n");

    ret = npu_open_sec();

    return ret;
}

unsigned int npu_syscall_release_cmdproc(npu_ops_release_info *command_info)
{
    int ret = 0;

    if (!command_info) {
        NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
        return -1;
    }

    NPU_DEBUG(" syscall release Enter:fd:%d \n",command_info->fd);

    ret = npu_release_sec(command_info->fd);

    return ret;
}

unsigned int npu_syscall_write_cmdproc(npu_ops_write_info *command_info)
{
    int ret = 0;

    if (!command_info) {
        NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
        return -1;
    }

    NPU_DEBUG(" syscall write Enter:fd:%d,buffer:0x%x,count:%d,fpos:%d \n",command_info->fd,command_info->buf,command_info->count,*(command_info->f_pos));

    ret = npu_write_sec(command_info->fd, command_info->buf, command_info->count, command_info->f_pos);

    return ret;
}

unsigned int npu_syscall_llseek_cmdproc(npu_ops_llseek_info *command_info)
{
    int ret = 0;

    if (!command_info) {
        NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
        return -1;
    }

    NPU_DEBUG(" syscall llseek Enter:fd:%d,off:%d,whence:%d \n",command_info->fd,command_info->off,command_info->whence);

    ret = npu_llseek_sec(command_info->fd, command_info->off, command_info->whence);

    return ret;
}

#include <hmdrv_stub.h>        // hack for `HANDLE_SYSCALL`
int npu_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{

    UINT32 uwRet = 0;
    /* According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them */
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_NPU_IOCTL_CFG, permissions, NPU_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(npu_ops_ioctl_info));
        if(args[0] == 0){
            NPU_ERR(" regs->r0 is NULL, FATAL arg and ignore\n");
            args[0] = OS_ERROR;
            return -1;
        }
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_ioctl_info));
        ACCESS_CHECK_A64(((npu_ops_ioctl_info *)(uintptr_t)args[0])->param, 11 * sizeof(unsigned int));
        ACCESS_WRITE_RIGHT_CHECK(((npu_ops_ioctl_info *)(uintptr_t)args[0])->param, 11 * sizeof(unsigned int));
        if ( FLUSH_DMA_ADDRESS == ((npu_ops_ioctl_info *)(uintptr_t)args[0])->cmd )
        {
            unsigned long start,tmp_size;
            start = ((npu_ops_ioctl_info *)(uintptr_t)args[0])->param[0];
            tmp_size = ((npu_ops_ioctl_info *)(uintptr_t)args[0])->param[1];

            ACCESS_CHECK_NOCPY(start,tmp_size);
            ACCESS_WRITE_RIGHT_CHECK(start,tmp_size);
            ((npu_ops_ioctl_info *)(uintptr_t)args[0])->param[0] = start;
            ((npu_ops_ioctl_info *)(uintptr_t)args[0])->param[1] = tmp_size;
        }

        uwRet = (UINT32)npu_syscall_ioctl_cmdproc((npu_ops_ioctl_info *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        //todo : add belove new system call in secos
        SYSCALL_PERMISSION(SW_SYSCALL_NPU_OPEN_MODE_CFG, permissions, NPU_GROUP_PERMISSION)
        uwRet = (UINT32)npu_syscall_open_cmdproc();
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_NPU_REALEASE_MODE_CFG, permissions, NPU_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(npu_ops_release_info));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_release_info));
        uwRet = (UINT32)npu_syscall_release_cmdproc((npu_ops_release_info *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_NPU_WRITE_INSTR_CFG, permissions, NPU_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(npu_ops_write_info));
        if(args[0] == 0){
            NPU_ERR("2 regs->r0 is NULL, FATAL arg and ignore\n");
            args[0] = OS_ERROR;
            return -1;
        }
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_write_info));
        ACCESS_CHECK_A64(((npu_ops_write_info *)(uintptr_t)args[0])->buf,
            ((npu_ops_write_info *)(uintptr_t)args[0])->count);
        ACCESS_WRITE_RIGHT_CHECK(((npu_ops_write_info *)(uintptr_t)args[0])->buf,
            ((npu_ops_write_info *)(uintptr_t)args[0])->count);
        ACCESS_CHECK_A64(((npu_ops_write_info *)(uintptr_t)args[0])->f_pos, sizeof(int));
        ACCESS_WRITE_RIGHT_CHECK(((npu_ops_write_info *)(uintptr_t)args[0])->f_pos, sizeof(int));
        uwRet = (UINT32)npu_syscall_write_cmdproc((npu_ops_write_info *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_NPU_LLSEEK_CFG, permissions, NPU_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(npu_ops_llseek_info));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_llseek_info));
        uwRet = (UINT32)npu_syscall_llseek_cmdproc((npu_ops_llseek_info *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END

    default:
        return -1;
    }
    return 0;
}

/* get common feature, in secure os no dtsi, write it fixed */
static int npu_common_get_features(void)
{
    FEATURE_S* p_feature = &adapter.common.feature;


#ifdef VERSION_V150
    p_feature->is_selfstart= 0;
    p_feature->core_num = 1;
#else
    p_feature->is_selfstart= 1;
    //todo: p_feature->core_num = MAX_SUPPORT_CORE_NUM;
    p_feature->core_num = 1;
#endif

    p_feature->level1_irq = 1;
    p_feature->performance_monitor = 1;
    p_feature->lpm3_set_vcodecbus = 1;
    p_feature->npu_reset_when_in_error = 2;
    p_feature->npu_bandwidth_lmt = 2;

    return 0;
}

static int npu_common_device_init(void)
{
    return 0;
}
static int npu_common_reset_init(void)
{
    NPU_MAIN_PRIVATE_COMMON_S* p_common = &adapter.common;
    PMCTRL_REG_S* pmctrl = &p_common->pmctrl_reg;
    PCTRL_REG_S* pctrl   = &p_common->pctrl_reg;
    MEDIA2_REG_S* media2 = &p_common->media2_reg;
    PERI_REG_S* peri     = &p_common->peri_reg;
    MEDIA1_REG_S* media1 = &p_common->media1_reg;
    DMSS_REG_S*   dmss   = &p_common->dmss;

    if (RESET_UNSUPPORT == p_common->feature.npu_reset_when_in_error) {
        NPU_DEBUG("feature reset is not support\n");
        return 0;
    }

    pmctrl->io_addr = SOC_ACPU_PMC_BASE_ADDR;
    pctrl->io_addr  = SOC_ACPU_PCTRL_BASE_ADDR;
    media2->io_addr = SOC_ACPU_MEDIA2_CRG_BASE_ADDR;
    media1->io_addr = SOC_ACPU_MEDIA1_CRG_BASE_ADDR;
    peri->io_addr   = SOC_ACPU_PERI_CRG_BASE_ADDR;
    dmss->io_addr   = SOC_DMSS_GLB_MST_FLUX_ADDR(SOC_ACPU_DMSS_BASE_ADDR, NPU_DCQ_DMSS_MSTS);
    return 0;
}

static void npu_common_device_exit(void)
{
    return;
}

/*reset exit*/
static void npu_common_reset_exit(void)
{
    NPU_MAIN_PRIVATE_COMMON_S* p_common = &adapter.common;

    if (RESET_UNSUPPORT == p_common->feature.npu_reset_when_in_error) {
        NPU_DEBUG("feature reset is not support\n");
        return;
    }
    p_common->dmss.io_addr = 0;
    p_common->peri_reg.io_addr = 0;
    p_common->media1_reg.io_addr = 0;
    p_common->media2_reg.io_addr = 0;
    p_common->pctrl_reg.io_addr = 0;
    p_common->pmctrl_reg.io_addr = 0;

    return;
}
static void npu_common_release_features(void)
{
    NPU_MAIN_PRIVATE_COMMON_S* p_common = &adapter.common;

    memset_s(&p_common->feature, sizeof(FEATURE_S), 0x0, sizeof(FEATURE_S));

    return;
}

/*get device features*/
static int npu_core_get_features(unsigned int coreid)
{
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("coreid[%d] err\n", coreid);
        return -1;
    }

    adapter.core[coreid].irq = NPU_DMA_IRQ_CORE0;
    //todo: adapter.core[coreid].irq = (0 == coreid)?NPU_DMA_IRQ_CORE0:NPU_DMA_IRQ_CORE1;
    return 0;
}

/* get device feature */
static int npu_core_reg_irq_init(unsigned int coreid)
{
    NPU_MAIN_PRIVATE_CORE_S* p_core;

    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("coreid[%d] err\n", coreid);
        return -1;
    }
    p_core = &adapter.core[coreid];

    if ( 0 == coreid )  {
        p_core->npu_irq.base_addr = SOC_ICS_IRQ_BASE_ADDR_CORE0;
    }
    else  {
        p_core->npu_irq.base_addr = SOC_ICS_IRQ_BASE_ADDR_CORE1;
    }

    p_core->npu_irq.io_addr = p_core->npu_irq.base_addr;
    return 0;
}

/* reset device feature*/
static void npu_core_reg_irq_exit(unsigned int coreid)
{
    NPU_MAIN_PRIVATE_CORE_S* p_core = &adapter.core[coreid];

    memset_s(&p_core->npu_irq, sizeof(NPU_IRQ_REG_S), 0x0, sizeof(NPU_IRQ_REG_S));

    return;
}

static int npu_common_init(void)
{
    int err = -1;

    /* get common_features */
    err = npu_common_get_features();
    if (err < 0) {
        NPU_ERR("fatal err, npu_common_get_features\n");
        return err;
    }

    err = npu_common_device_init();
    if (err < 0) {
        NPU_ERR("Failed npu_common_device_init!\n");
        goto reset_features;
    }

    err = npu_common_reset_init();
    if (err < 0) {
        NPU_ERR("Failed npu_common_reset_init!\n");
        goto device_exit;
    }

    NPU_DEBUG("Succeeded to npu_common_init.\n");

    return 0;

device_exit:
    npu_common_device_exit();

reset_features:
    npu_common_release_features();

    return err;
}

/*common exit*/
static void npu_common_exit(void)
{
    npu_common_reset_exit();

    npu_common_device_exit();

    npu_common_release_features();

    return;
}

/*reset device features*/
static void npu_core_release_features(unsigned int coreid)
{
    adapter.core[coreid].irq = 0;

    return;
}

/*irq handle*/
static void npu_core_irq_handler_func(unsigned int coreid)
{
    unsigned int irq_io_addr = adapter.core[coreid].npu_irq.io_addr;

    if (adapter.common.feature.level1_irq) {
        npu_core_irq_handler(coreid, irq_io_addr);
    }
    else {
        /* clear npu finished status */
        npu_task_finish_interrupt_clear(coreid);
        writel(NPU_IRQ_CLEAR_IRQ_S, SOC_ICS_IRQ_CLR_S_ADDR(irq_io_addr));
    }
    return;
}

/*interrupt handler*/
static int npu_interrupt_handler(unsigned int *ptr)
{
    unsigned int coreid = 0;
    unsigned int irq = 0;
    bool smmu_err_isr = false;

    NPU_DEBUG("irq come\n");

    if (ptr == NULL) {
        NPU_ERR("Input null point. \n");
        return -1;
    }

    irq = *ptr;


    for (coreid = 0; coreid < MAX_SUPPORT_CORE_NUM; coreid++) {
        if (adapter.core[coreid].irq == irq) {
            break;
        }
    }

    if (coreid == MAX_SUPPORT_CORE_NUM) {
        NPU_ERR("invalid irq = %d\n", irq);
        return -1;
    }

    CTRL_LOCK(coreid);

    if (!npu_chip_can_direct_access(coreid)) {
        CTRL_UNLOCK(coreid);

        NPU_ERR("npu is work off, ignore\n");

        return -1;
    }

    /*smmu interrupt handler*/
    smmu_err_isr = npu_smmu_interrupt_handler(coreid);
    if (smmu_err_isr) {
        npu_reset_proc(coreid);
        npu_task_restore(coreid);
    } else {
        npu_core_irq_handler_func(coreid);
    }

    CTRL_UNLOCK(coreid);

    return 0;
}

/*core module device init*/
static int npu_core_init(unsigned int coreid)
{
    int err = -1;
    unsigned int uRet = 0;
    NPU_MAIN_PRIVATE_CORE_S* p_core = &adapter.core[coreid];

    if(pthread_mutex_init(&p_core->ctrl_mutex, NULL)){
        NPU_ERR("Failed to pthread_mutex_init ctrl_mutex\n");
    }
    if(pthread_mutex_init(&p_core->mode_mutex, NULL)){
        NPU_ERR("Failed to pthread_mutex_init mode_mutex\n");
    }

    p_core->security_mode = NON_SECURETY;

    err = npu_core_get_features(coreid);
    if (err < 0){
        NPU_ERR("coreid[%d], Failed to get device features!\n", coreid);
        return -1;
    }

    err = npu_core_reg_irq_init(coreid);
    if (err){
        NPU_ERR("coreid[%d], failed npu_core_reg_irq_init\n", coreid);
        goto core_reset_features;
    }

    /* request npu irq */
    uRet = SRE_HwiCreate((HWI_HANDLE_T)p_core->irq, (HWI_PRIOR_T)0, (HWI_MODE_T)0,
            (HWI_PROC_FUNC)npu_interrupt_handler, (unsigned int)&p_core->irq);
    if (uRet) {
        NPU_ERR("NPU%d Require IRQ failed!, uRet = %d\n", coreid, uRet);
        err = -1;
        goto core_reg_irq_exit;
    }

    NPU_DEBUG("Succeeded to npu_core_init coreid[%d].\n", coreid);

    return 0;

core_reg_irq_exit:
    npu_core_reg_irq_exit(coreid);

core_reset_features:
    npu_core_release_features(coreid);

    return err;
}

/*core module device exit*/
static void npu_core_exit(unsigned int coreid)
{
    NPU_MAIN_PRIVATE_CORE_S* p_core = &adapter.core[coreid];

    SRE_HwiDelete((HWI_HANDLE_T)p_core->irq);

    npu_core_reg_irq_exit(coreid);

    npu_core_release_features(coreid);

    p_core->security_mode = NON_SECURETY;

    pthread_mutex_destroy(&p_core->mode_mutex);
    pthread_mutex_destroy(&p_core->ctrl_mutex);

    return;
}

static int npu_main_init(void)
{
    int err = -1;
    int coreid = 0;

    memset_s(&adapter, sizeof(NPU_MAIN_PRIVATE_S), 0, sizeof(NPU_MAIN_PRIVATE_S));

    err = npu_common_init();
    if (err < 0) {
        NPU_ERR("Failed to init common!\n");
        return err;
    }

    for (coreid = 0; coreid < (int)(adapter.common.feature.core_num); coreid++) {
        err = npu_core_init(coreid);
        if (err < 0) {
            NPU_ERR("Failed npu_core_init coreid[%d]!\n", coreid);
            goto common_exit;
        }
    }

    return 0;

common_exit:
    for (; coreid > 0; coreid--) {
        npu_core_exit(coreid - 1);
    }

    npu_common_exit();

    return err;
}

static void npu_main_exit(void)
{
    unsigned int coreid = 0;

    for (coreid = 0; coreid < adapter.common.feature.core_num; coreid++) {
        npu_core_exit(coreid);
    }

    npu_common_exit();

    memset_s(&adapter, sizeof(NPU_MAIN_PRIVATE_S), 0x0, sizeof(NPU_MAIN_PRIVATE_S));

    return;
}

void npu_common_lock(unsigned int coreid)
{
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return;
    }

    COMMON_LOCK(coreid);
    return;
}

void npu_common_unlock(unsigned int coreid)
{
    if (coreid > adapter.common.feature.core_num - 1) {
        NPU_ERR("param err coreid[%d]!", coreid);
        return;
    }

    COMMON_UNLOCK(coreid);
    return;
}

static int npu_probe_sec(void)
{
    int err = -1;
    int coreid;
    NPU_CALLBACK_FUNC_S callback;

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_KIRIN990)
    memset_s(&callback, sizeof(NPU_MAIN_PRIVATE_S), 0x0, sizeof(NPU_CALLBACK_FUNC_S));

    callback.pf_npu_reset             = (NPU_RESET_CALLBACK_FUNC)npu_reset;
    callback.pf_npu_common_lock       = (NPU_COMMON_LOCK_FUNC)npu_common_lock;
    callback.pf_npu_common_unlock     = (NPU_COMMON_LOCK_FUNC)npu_common_unlock;

    err = npu_main_init();
    if (err < 0) {
        NPU_ERR("Failed npu_main_init!\n");
        goto failed;
    }

    err = npu_smmu_mngr_init();
    if (err < 0) {
        NPU_ERR("Failed npu_smmu_mngr_init!\n");
        goto main_exit;
    }

    err = npu_task_init(adapter.common.feature.core_num, &callback);
    if (err < 0) {
        NPU_ERR("Failed npu_task_init!\n");
        goto smmu_exit;
    }

    NPU_PRINT("Succeeded to initialize npu device.\n");

    for (coreid = 0; coreid < (int)(adapter.common.feature.core_num); coreid++) {
        MODE_LOCK(coreid);
    }

    return 0;

smmu_exit:
    npu_smmu_mngr_exit();

main_exit:
    npu_main_exit();

failed:
    return err;
#endif
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE)
DECLARE_TC_DRV(
    npu_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    npu_probe_sec,
    NULL,
    npu_syscall,
    NULL,
    NULL
);
#endif

