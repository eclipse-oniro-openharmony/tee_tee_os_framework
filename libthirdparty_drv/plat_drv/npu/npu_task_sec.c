
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
#include "npu_task_public_sec.h"
#include "npu_task_wq_sec.h"
#include "npu_task_sswq_sec.h"

#define INTERRUPTINST_INTERRUPT_BIT     (7)
#define INTERRUPTINST_INTERRUPT_MASK    (0x1UL<<INTERRUPTINST_INTERRUPT_BIT)
#define CT_INTERRUPT_BIT                (6)
#define CT_INTERRUPT_MASK               (0x1UL<<CT_INTERRUPT_BIT)
#define NPU_CONTROL_INTERRUPT_BIT       (5)
#define NPU_CONTROL_INTERRUPT_MASK      (0x1UL<<NPU_CONTROL_INTERRUPT_BIT)
#define WATCH_DOG_BIT                   (4)
#define WATCH_DOG_MASK                  (0x1UL<<WATCH_DOG_BIT)
#define IS_NORMAL_FINISH_BIT            (0)
#define IS_NORMAL_FINISH_MASK           (0x1UL<<IS_NORMAL_FINISH_BIT)

#define NPU_CHECK_CORE_NUM_VALID(core_num) (core_num > MAX_SUPPORT_CORE_NUM)

#define NPU_SSWQ_TASK_IRQ_MASK (WORK_QUEUE_ALL_FINISH_IS_MASK | WORK_QUEUE_MASK_FINISH_IS_MASK | WORK_QUEUE_FINISH_IS_MASK)

#define NPU_CONF_REG_ADDRESS_CORE0    (0xFF400000)
#define NPU_CONF_REG_SIZE_CORE0       (0x00100000)

#define NPU_INST_RAM_ADDRESS_CORE0    (0xFF500000)
#define NPU_INST_RAM_SIZE_CORE0       (0x00100000)       /*64k*/

#ifdef NPU_VERSION_V200
#define NPU_CONF_REG_ADDRESS_CORE1    (0xE9000000)
#define NPU_CONF_REG_SIZE_CORE1       (0x00100000)

#define NPU_INST_RAM_ADDRESS_CORE1    (0xE9100000)
#define NPU_INST_RAM_SIZE_CORE1       (0x00100000)       /*64k*/
#endif

#define SOC_ICS_IRQ_CLR_S_ADDR(base)                  ((base) + (0x001C))

NPU_TASK_PRIVATE_S g_task_private;

int npu_task_read_dword(unsigned int core_id, int offset)
{
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    if (NPU_VERSION_REG == offset) {
        return readl(config_reg_virt_addr + offset);
    }

    NPU_ERR("Input parameter error!");
    return -1;
}

int npu_task_write_dword(unsigned int core_id, int offset, int data)
{
    if ((NPU_START_REG == offset) || (NPU_STATUS_REG == offset) || (NPU_BASE_ADDR_REG == offset)) {
        writel(data, g_task_private.reg_space[core_id].config_reg_virt_addr + offset);
        return SUCCESS;
    }

    NPU_ERR("error offset when npu on, offset=0x%pK",(void *)offset);
    return -1;
}

int npu_task_llseek_proc(unsigned int core_id, int file_pos, int off, int whence)
{
    int pos;
    NPU_REG_SPACE_S* reg_space_ptr = NULL;

    reg_space_ptr = &g_task_private.reg_space[core_id];
    if (NULL == reg_space_ptr) {
        NPU_ERR("Input parameter is error!core_id:%d", core_id);
        return -1;
    }

    /* covert unsigned int(32bit) to long(64bit), with no risk */
    if ((off > (int)reg_space_ptr->inst_ram_size) || (off < (-1 * (int)reg_space_ptr->inst_ram_size))) {
        NPU_ERR("invalid offset=0x%pK while inst_ram_size=0x%x\n", (void *)off, reg_space_ptr->inst_ram_size);
        return -1;
    }

    pos = file_pos;
    switch (whence) {
    /* Set f_pos */
    case 0: /* SEEK_SET */
        pos = off;
        break;
    /* Move f_pos forward */
    case 1: /* SEEK_CUR */
        pos += off;
        break;
    /* More */
    case 2: /* SEEK_END */
        break;
    /* Default Operation */
    default:
        return -1;
    }

    if ((pos >= (int)reg_space_ptr->inst_ram_size) || (pos < 0)) {
        NPU_ERR("Move file position out of range!");
        return -1;
    }

    return pos;
}

int npu_task_write_inst(unsigned int core_id, const char *buf, unsigned int count, int file_pos)
{
    int ret_value = 0;
    NPU_REG_SPACE_S* reg_space_ptr = NULL;

    reg_space_ptr = &g_task_private.reg_space[core_id];
    if (NULL == reg_space_ptr) {
        NPU_ERR("Input parameter is error!core_id:%d", core_id);
        return -1;
    }

    if (count == 0 || count > reg_space_ptr->inst_ram_size) {
        NPU_ERR("Input parameter count is invalid!");
        return -1;
    }

    if ((file_pos < 0) || (file_pos > (int)reg_space_ptr->inst_ram_size)) {
        NPU_ERR("Write file position out of range!");
        return -1;
    }

#ifdef VERSION_V150
    /* NPU off, write to temp buff "adapter->boot_inst_set.boot_inst" */
    ret_value = npu_write_when_npu_down(reg_space_ptr, buf, count, file_pos);
    if (ret_value < 0) {
        NPU_ERR("write 0x%x bytes, offset=0x%x error,return is %d\n", count, file_pos, ret_value);
    } else {
        NPU_DEBUG("write 0x%x bytes, file_pos=%d\n", ret_value, file_pos);
    }
#else
    if ((file_pos + (int)count) > ((int)reg_space_ptr->inst_ram_size)){
        count = (unsigned int)(reg_space_ptr->inst_ram_size - file_pos);
    }
    memcpy_s((void *)((int)reg_space_ptr->inst_ram_virt_addr + file_pos), count,(void *)buf, count);
#endif

    return ret_value;
}

int npu_push_task(unsigned int* arg, unsigned int irq_num)
{
    int ret = SUCCESS;
    NPU_SSWQ_TASK_ELEMENT_S task;

    if (!arg) {
        NPU_ERR("Input parameter is NULL!");
        return -1;
    }

    memset_s(&task, sizeof(NPU_SSWQ_TASK_ELEMENT_S), 0, sizeof(NPU_SSWQ_TASK_ELEMENT_S));

    task.core_id = arg[0];
    task.task_type = arg[1];
    if (NPU_SSWQU_TASK_ENUM_END <= task.task_type) {
        NPU_ERR("Input task type is error! task_type=%d", task.task_type);
        return -1;
    }
    task.inst_size     = arg[2];
    task.task_id       = arg[3];
    task.thread_id     = arg[4];
    task.task_config   = arg[5];
    task.task_priority = arg[6];
    task.inst_addr_off = NPU_DUALINT_TO_LONG(arg[8],arg[7]);
    task.ddr_base_addr = NPU_DUALINT_TO_LONG(arg[10],arg[9]);

    NPU_PRINT("Core_id %d, Task-Type %d, Task-Prio %d, I-Size 0x%x, Task-Id 0x%x, Thread-Id 0x%x, Config 0x%x",
                task.core_id,
                task.task_type,
                task.task_priority,
                task.inst_size,
                task.task_id,
                task.thread_id,
                task.task_config);

    NPU_PRINT("I-Addr: low32bit=0x%llx high32bit=0x%llx", (task.inst_addr_off & 0xffffffff), ((task.inst_addr_off>>32) & 0xffffffff));
    NPU_PRINT("DDR-Base: low32bit=0x%llx high32bit=0x%llx", (task.ddr_base_addr & 0xffffffff), ((task.ddr_base_addr>>32) & 0xffffffff));

#ifdef VERSION_V150
    ret = npu_push_wq_task((const void *)&task, irq_num);
    if (SUCCESS != ret) {
        NPU_ERR("Call NPU_sswq_push_task failed! ret=%d", ret);
        return -1;
    }
#else
    ret = npu_push_sswq_task((const void *)&task);
    if (SUCCESS != ret) {
        NPU_ERR("Call NPU_sswq_push_task failed! ret=%d", ret);
        return -1;
    }
    UNUSED_PARAMETER(irq_num);
#endif
    return SUCCESS;
}

int npu_task_fifo_opt_lock(unsigned int core_id)
{
    if (NULL == g_task_private.callback_fun.pf_npu_common_lock) {
        NPU_ERR("Input parameter is NULL!");
        return -1;
    }
    g_task_private.callback_fun.pf_npu_common_lock(core_id);

    return SUCCESS;
}

int npu_task_fifo_opt_unlock(unsigned int core_id)
{
    if (NULL == g_task_private.callback_fun.pf_npu_common_unlock) {
        NPU_ERR("Input parameter is NULL!");
        return -1;
    }
    g_task_private.callback_fun.pf_npu_common_unlock(core_id);

    return SUCCESS;
}

static void npu_task_callback_fun_init(NPU_CALLBACK_FUNC_S* callback_fun_ptr)
{
    memcpy_s(&g_task_private.callback_fun, sizeof(NPU_CALLBACK_FUNC_S), callback_fun_ptr, sizeof(NPU_CALLBACK_FUNC_S));
    return;
}

int npu_task_finish_interrupt_clear(unsigned int core_id)
{
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    /* clear NPU finished status, ICS_STATUS.ics_status=0: not finish */
    writel(NPU_STATUS_UNFINISH, SOC_ICS_STATUS_ADDR(config_reg_virt_addr));

    return SUCCESS;
}

int npu_task_reset_proc(unsigned int core_id)
{
    if (NULL == g_task_private.callback_fun.pf_npu_reset) {
        NPU_ERR("Input parameter is NULL!");
        return -1;
    }
    g_task_private.callback_fun.pf_npu_reset(core_id);

    return SUCCESS;
}

void npu_task_restore(unsigned int core_id)
{
#ifdef VERSION_V150
    npu_wq_task_restore(core_id);
#else
    npu_sswq_task_restore(core_id);
#endif
    return;
}

void npu_task_watchdog_start(unsigned int core_id)
{
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;
    unsigned long long watchdog_timeout = g_task_private.watchdog_timer[core_id];
    unsigned int tmp;

    NPU_DEBUG("Enter npu_task_watchdog_start!core_id=%d watchdog_timeout=0x%llx", core_id, watchdog_timeout);
    tmp = (unsigned int)(watchdog_timeout & 0xffffffff);
    NPU_DEBUG("Enter npu_task_watchdog_start!core_id=%d low32bit=%d", core_id, tmp);
    writel(tmp, SOC_NPU_WATCH_DOG_TIMER_LOW_ADDR(config_reg_virt_addr));

    tmp = (unsigned int)((watchdog_timeout>>32) & 0xffffffff);
    NPU_DEBUG("Enter npu_task_watchdog_start!core_id=%d high32bit=%d", core_id, tmp);
    writel(tmp, SOC_NPU_WATCH_DOG_TIMER_HIGH_ADDR(config_reg_virt_addr));
    return;
}

static void npu_core_irq_clear(unsigned int core_id, unsigned int irq_io_addr, unsigned int* interrupt_status_ptr)
{
    bool reset_npu_flag = false;
    unsigned int interrupt_status;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    interrupt_status = readl(SOC_NPU_IS_ADDR(config_reg_virt_addr));
    interrupt_status_ptr[core_id] = interrupt_status;
    while(interrupt_status){
        NPU_PRINT("lv1_int_status=0x%x", interrupt_status);

        /********************NPU_INTERRUPT*******************/
        if (interrupt_status & CT_INTERRUPT_MASK) {
            reset_npu_flag = true;
        }

        /********************NPU_CONTROL_INTERRUPT**********/
        if (interrupt_status & NPU_CONTROL_INTERRUPT_MASK) {
            reset_npu_flag = true;
        }

        /********************WATCH_DOG**********************/
        if (interrupt_status & WATCH_DOG_MASK) {
            reset_npu_flag = true;
        }

         /********************self start interrupt*******************/
        if (interrupt_status & NPU_SSWQ_TASK_IRQ_MASK) {
            npu_sswq_get_interrupt_status(core_id);
            npu_sswq_workqueue_finish_reg_clear(core_id);
        }

        if (interrupt_status & IS_NORMAL_FINISH_MASK) {
            /* to clear normal finish reg */
            writel(NPU_STATUS_UNFINISH, SOC_ICS_STATUS_ADDR(config_reg_virt_addr));
        }

        /* to clear finish reg */
        writel(interrupt_status, SOC_NPU_IS_ADDR(config_reg_virt_addr));
        /* to clear finish reg high 32bit */
        writel(0, SOC_NPU_IS_ADDR(config_reg_virt_addr + 0X4));
        interrupt_status = readl(SOC_NPU_IS_ADDR(config_reg_virt_addr));

        if (reset_npu_flag) {
            break;
        }
    }

    /* to  clear non-secure interrupt */
    writel(NPU_IRQ_CLEAR_IRQ_LEVEL1_S | NPU_IRQ_CLEAR_IRQ_S, SOC_ICS_IRQ_CLR_S_ADDR(irq_io_addr));

    return;
}

static void npu_core_irq_task_proc(unsigned int core_id, unsigned int* interrupt_status_ptr)
{
    bool reset_npu_flag = false;
    unsigned int interrupt_status = interrupt_status_ptr[core_id];
    unsigned int fault_status = 0;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    if (!interrupt_status) {
        NPU_ERR("interrupt status is error!interrupt_status=%d", interrupt_status);
        return;
    }

    /*******************INTERRUPTINST_INTERRUPT***********/
    if (interrupt_status & INTERRUPTINST_INTERRUPT_MASK) {
        fault_status = readl(SOC_NPU_INTERRUPT_INST_ADDR(config_reg_virt_addr));
        writel(0, SOC_NPU_INTERRUPT_INST_ADDR(config_reg_virt_addr));
        NPU_ERR("core_id %d INTERRUPTINST_INTERRUPT, fault_status=0x%x", core_id, fault_status);
    }

    /********************NPU_INTERRUPT*******************/
    if (interrupt_status & CT_INTERRUPT_MASK) {
        NPU_ERR("core_id %d CT_INTERRUPT, fault_status=0x%x", core_id, fault_status);

        reset_npu_flag = true;
    }

    /********************NPU_CONTROL_INTERRUPT**********/
    if (interrupt_status & NPU_CONTROL_INTERRUPT_MASK) {
        fault_status = readl(SOC_NPU_INTERRUPT_INST_ADDR(config_reg_virt_addr));
        
        NPU_ERR("core_id %d NPU_CONTROL_INTERRUPT, NPU_INTERRUPT_INST(0xAC)=0x%x, npu_control id:%x%x",
                 core_id,
                 fault_status,
                 readl((SOC_NPU_CONTROL_ID_ADDR(config_reg_virt_addr + 4))),
                 readl(SOC_NPU_CONTROL_ID_ADDR(config_reg_virt_addr)));

        NPU_ERR("core_id %d NPU_CONTROL_INTERRUPT, NPU_INTERRUPT_PC(0xB0)=0x%x",
                 core_id,
                 readl(SOC_NPU_INTERRUPT_PC_ADDR(config_reg_virt_addr)));

        reset_npu_flag = true;
    }

    /********************WATCH_DOG**********************/
    if (interrupt_status & WATCH_DOG_MASK) {
        /* do_watch_dog_interrupt_service();*/
        NPU_ERR("core_id %d WATCH_DOG, fault_status=0x%x", core_id, fault_status);
        reset_npu_flag = true;
    }

    if (reset_npu_flag) {
        /* reset npu */
        npu_task_reset_proc(core_id);
        /* restore task */
        npu_task_restore(core_id);
        return;
    }

    /********************self start interrupt*******************/
    if (interrupt_status & NPU_SSWQ_TASK_IRQ_MASK) {

        npu_sswq_core_interrupt_handler(core_id);

        npu_sswq_interrupt_msg_clear(core_id);
    }

    /********************NORMAL_FINISH*******************/
    if (interrupt_status & IS_NORMAL_FINISH_MASK) {

        npu_start_wq_next_task(core_id);
    }

    return;
}


void npu_core_irq_handler(unsigned int core_id, unsigned int irq_io_addr)
{
    unsigned int interrupt_status[MAX_SUPPORT_CORE_NUM] = {0};

    npu_core_irq_clear(core_id, irq_io_addr, interrupt_status);
    npu_core_irq_task_proc(core_id, interrupt_status);
    return;
}

static int npu_task_get_reg_space(int core_id)
{
    NPU_REG_SPACE_S* reg_space_ptr = NULL;

    reg_space_ptr = &g_task_private.reg_space[core_id];
    if (NULL == reg_space_ptr) {
        NPU_ERR("Input parameter is error!core_id:%d", core_id);
        return -1;
    }

    reg_space_ptr->config_reg_phys_addr = (0 == core_id)?NPU_CONF_REG_ADDRESS_CORE0:NPU_CONF_REG_ADDRESS_CORE1;
    reg_space_ptr->config_reg_length = (0 == core_id)?NPU_CONF_REG_SIZE_CORE0:NPU_CONF_REG_SIZE_CORE1;

    NPU_DEBUG("coreid[%d], config_reg_phys_addr[0x%pK], config_reg_length[0x%x]",
                core_id, reg_space_ptr->config_reg_phys_addr, reg_space_ptr->config_reg_length);

    reg_space_ptr->config_reg_virt_addr = reg_space_ptr->config_reg_phys_addr;

    reg_space_ptr->inst_ram_phys_addr = (0 == core_id)?NPU_INST_RAM_ADDRESS_CORE0:NPU_INST_RAM_ADDRESS_CORE1;
    reg_space_ptr->inst_ram_size = (0 == core_id)?NPU_INST_RAM_SIZE_CORE0:NPU_INST_RAM_SIZE_CORE1;

    NPU_DEBUG("coreid[%d], inst_ram_phys_addr[0x%pK], inst_ram_size[0x%x]\n",
                core_id, reg_space_ptr->inst_ram_phys_addr, reg_space_ptr->inst_ram_size);

    reg_space_ptr->inst_ram_virt_addr = reg_space_ptr->inst_ram_phys_addr;

    return SUCCESS;
}

static int npu_task_reg_space_init(void)
{
    int ret = SUCCESS;
    unsigned int core_id;

    for(core_id = 0; core_id < g_task_private.core_num; core_id++) {
        ret = npu_task_get_reg_space(core_id);
        if (ret) {
            NPU_ERR("Call npu_task_get_reg_space is failed!");
        }
    }

    return ret;
}

static void npu_task_reg_space_release(void)
{
    unsigned int core_id;
    NPU_REG_SPACE_S* reg_space = NULL;

    for (core_id = 0; core_id < g_task_private.core_num; core_id++) {

        reg_space = &g_task_private.reg_space[core_id];
        reg_space->config_reg_virt_addr = 0;
        reg_space->inst_ram_virt_addr = 0;
    }

    return;
}

static void npu_task_watchdog_timer_init(void)
{
    unsigned int core_id;

    for(core_id = 0; core_id < g_task_private.core_num; core_id++) {
        g_task_private.watchdog_timer[core_id] = NPU_WATCHDOG_TIMEOUT;
    }

    return;
}

int npu_task_init(unsigned int core_num, NPU_CALLBACK_FUNC_S* callback_fun_ptr)
{
    int ret = SUCCESS;
    int ret_value;

    if ((NULL == callback_fun_ptr) || (NPU_CHECK_CORE_NUM_VALID(core_num))) {
        NPU_ERR("Input parameter error!core_num=%d", core_num);
        return -1;
    }

    memset_s(&g_task_private, sizeof(NPU_TASK_PRIVATE_S), 0, sizeof(NPU_TASK_PRIVATE_S));

    g_task_private.core_num = core_num;

    npu_task_callback_fun_init(callback_fun_ptr);

    ret = npu_task_reg_space_init();
    if (ret) {
        NPU_ERR("Call npu_task_reg_space_init is failed!");
        ret_value = -1;
        goto free;
    }

#ifdef VERSION_V150
    ret = npu_task_wq_init();
    if (ret) {
        NPU_ERR("Failed npu_task_wq_init!");
        ret_value = -1;
        goto task_init_error;
    }
#else
    ret = npu_task_sswq_init();
    if (ret) {
        NPU_ERR("Failed npu_task_sswq_init!");
        ret_value = -1;
        goto task_init_error;
    }
#endif

    npu_task_watchdog_timer_init();
    return SUCCESS;

task_init_error:
    npu_task_reg_space_release();
free:
    memset_s(&g_task_private, sizeof(NPU_TASK_PRIVATE_S), 0, sizeof(NPU_TASK_PRIVATE_S));

    return ret_value;

}

void npu_task_exit(void)
{
#ifdef VERSION_V150
    npu_task_wq_exit();
#else
    npu_task_sswq_exit();
#endif

    memset_s(&g_task_private, sizeof(NPU_TASK_PRIVATE_S), 0, sizeof(NPU_TASK_PRIVATE_S));

    return;
}

