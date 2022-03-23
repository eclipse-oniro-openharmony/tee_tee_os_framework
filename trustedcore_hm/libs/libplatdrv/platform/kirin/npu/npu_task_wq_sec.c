#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"

#include <sre_typedef.h>
#include <sre_sys.h>
#include <mem_ops.h>
#include <register_ops.h> // writel
#include <sre_hwi.h>
#include <tee_defines.h>
#include <sys/hmapi_ext.h>

#include "stdint.h"
#include "drv_module.h"
#include "libhwsecurec/securec.h"

#include "npu_public_sec.h"
#include "npu_task_public_sec.h"
#include "npu_task_wq_sec.h"

#define TASKQUEUE_SIZE      (64)
#define BOOT_INST_SIZE      (64)
#define BOOT_INST_NUMBER    (5)

/*check whether the parameter is effective*/
#define CHECK_TASK_TYPE(taskType) ((NPU_COMPUTE_TASK == taskType) || (NPU_SYNC_TASK == taskType))

/* this struct stores the temp data of boot instrument for NPU initialization after power-up */
typedef struct {
    /* store the value from IOCTL WRITE when NPU is off */
    unsigned int npu_access_ddr_addr;

    /* boot-instrument data */
    unsigned char boot_inst[BOOT_INST_SIZE * BOOT_INST_NUMBER];

    unsigned char boot_inst_tmp[BOOT_INST_SIZE * BOOT_INST_NUMBER];

    /* size of boot-inst data */
    unsigned int boot_inst_size;

    /* bool flag to record whether access_ddr_addr is recorded */
    bool access_ddr_addr_is_config;

    /* bool flag to record whether boot_inst is recorded */
    bool boot_inst_recorded_is_config;
} NPU_BOOT_INST_S;

typedef struct {
    NPU_BOOT_INST_S boot_inst_set;
} NPU_TASK_WQ_PRIVATE_S;

NPU_TASK_WQ_PRIVATE_S task_wq_private;

int npu_task_wq_init(void)
{
    memset_s(&task_wq_private, sizeof(NPU_TASK_WQ_PRIVATE_S), 0x0, sizeof(NPU_TASK_WQ_PRIVATE_S));

    return SUCCESS;
}

void npu_task_wq_exit(void)
{
    memset_s(&task_wq_private, sizeof(NPU_TASK_WQ_PRIVATE_S), 0x0, sizeof(NPU_TASK_WQ_PRIVATE_S));

    return;
}

int npu_task_set_boot_inst(unsigned int core_id, bool cfg_flag, unsigned int data)
{
    if (0 != core_id) {
        NPU_ERR("Input parameter is error!core_id:%d", core_id);
        return -1;
    }

    task_wq_private.boot_inst_set.npu_access_ddr_addr = data;
    task_wq_private.boot_inst_set.access_ddr_addr_is_config = cfg_flag;

    return SUCCESS;
}

int npu_write_when_npu_down(NPU_REG_SPACE_S* reg_space, const char *buf, unsigned int count, unsigned int file_pos)
{
    int ret_value;
    unsigned int max_buff_size = reg_space->inst_ram_size;

    if (max_buff_size > sizeof(task_wq_private.boot_inst_set.boot_inst)) {
        max_buff_size = sizeof(task_wq_private.boot_inst_set.boot_inst);
    }

    /* NOTE: here max_buff_size is a 32bit length data, and above judge can guarantee (*f_pos + count) < 2*max_buff_size so OVERFLOW in "unsigned long" is impossible here */
    if((file_pos + count) > max_buff_size) {
        NPU_ERR("FATAL, count OVERFLOW, *f_pos=0x%pK, count= 0x%x", (void *)file_pos, count);
        return -1;
    }

    if (task_wq_private.boot_inst_set.boot_inst_recorded_is_config) {
        NPU_ERR("NPU_WARN:boot_inst to overwrite old data!");
    }

    /* clean-up buffer and recv new data */
    memset_s(&task_wq_private.boot_inst_set.boot_inst[0], sizeof(task_wq_private.boot_inst_set.boot_inst),
            0, sizeof(task_wq_private.boot_inst_set.boot_inst));

    memcpy_s((void *)(&task_wq_private.boot_inst_set.boot_inst[0] + file_pos), count, buf, count);

    task_wq_private.boot_inst_set.boot_inst_recorded_is_config = true;
    /* because above guarentees (*f_pos + count <= dev->inst_ram_size), dev->inst_ram_size is uint16, so "+" CAN NOT get overflow */
    task_wq_private.boot_inst_set.boot_inst_size = (count + file_pos);
    ret_value = (int)count;

    return ret_value;
}

int set_offchip_inst_addr(unsigned int core_id, unsigned long long addr)
{
    unsigned int i;
    unsigned int tmp;
    NPU_REG_SPACE_S* reg_space = NULL;

    UNUSED_PARAMETER(addr);

    reg_space = &g_task_private.reg_space[core_id];
    if (NULL == reg_space) {
        NPU_ERR("Input parameter is NULL!");
        return -1;
    }

    /* write boot inst to instram */
    for (i = 0; i < task_wq_private.boot_inst_set.boot_inst_size; i += 4) {
        tmp = *(unsigned int *)&task_wq_private.boot_inst_set.boot_inst_tmp[i];
        writel(tmp, (reg_space->inst_ram_virt_addr + i));
    }

    return SUCCESS;
}

static void change_inst_data(unsigned long long data, int site)   {
    int tmp, tmp1, i,j;
    unsigned char *inst = (unsigned char *)(&task_wq_private.boot_inst_set.boot_inst_tmp[0]) ;
    tmp = site/8+1;
    tmp1 = site%8;
    if (!tmp1)
        for ( i=56,j=tmp; j<tmp+8; i-=8, j++)
            inst [128 - j] = (data >> i & 0xff);
    else {
        inst[128 - tmp] |= ((data >> (56+tmp1)) & ((0x1 <<(9-tmp1)) -1));
        inst[120 - tmp] |= (data & ((0x1 <<(tmp1 +1)) -1) )<< (8-tmp1);
        for ( i=56 - (8-tmp1),j=tmp+1; j<tmp+8; i-=8, j++)
            inst [64*1 + 64 - j] = (data >> i & 0xff);
    }
}

#define SET_INST_ADDR(addr)   \
({\
    change_inst_data(addr, 87);   \
})
#define SET_INST_SIZE(size)   \
({\
    change_inst_data(size, 152);   \
    change_inst_data(size, 283);   \
    change_inst_data(size, 21);    \
})

static int npu_start_wq_task(unsigned int core_id, taskElement* head)
{
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;
    NPU_BOOT_INST_S* boot_inst_set = NULL;
    NPU_REG_SPACE_S* reg_space = NULL;

    boot_inst_set = &task_wq_private.boot_inst_set;

    reg_space = &g_task_private.reg_space[core_id];


    npu_task_watchdog_start(core_id);

    /* prepare data for npu */
    if (NPU_TO_START != readl(SOC_ICS_START_ADDR(config_reg_virt_addr))) {
        memset_s(&boot_inst_set->boot_inst_tmp[0], sizeof(boot_inst_set->boot_inst_tmp),
            0, sizeof(boot_inst_set->boot_inst_tmp));
        memcpy_s(&boot_inst_set->boot_inst_tmp[0], sizeof(boot_inst_set->boot_inst_tmp),
            &boot_inst_set->boot_inst[0], sizeof(boot_inst_set->boot_inst_tmp));
        SET_INST_SIZE(head->offchipInstSize);
        SET_INST_ADDR(head->offchipInstAddr);

        set_offchip_inst_addr(core_id, 0);
        writel(boot_inst_set->npu_access_ddr_addr, SOC_ICS_BASE_ADDR_ADDR(config_reg_virt_addr));

        /* start ipu */
        writel(NPU_TO_STOP, SOC_ICS_START_ADDR(config_reg_virt_addr));
        writel(NPU_STATUS_UNFINISH, SOC_ICS_STATUS_ADDR(config_reg_virt_addr));
        writel(NPU_TO_START, SOC_ICS_START_ADDR(config_reg_virt_addr));
        g_task_private.start_task[core_id].state = NPU_TASK_START_DOING;

        NPU_DEBUG("START COMPUTE, offchipInstAddr: low32bit=0x%llx high32bit=0x%llx", (head->offchipInstAddr & 0xffffffff), ((head->offchipInstAddr>>32) & 0xffffffff));
    }

    UNUSED_PARAMETER(reg_space);

    return SUCCESS;
}

bool npu_get_wq_task(unsigned int core_id)
{
    if (NPU_TASK_START_DOING == g_task_private.start_task[core_id].state) {
        g_task_private.start_task[core_id].state = NPU_TASK_START_DONE;
    } else {
        NPU_ERR("start_task state is NPU_TASK_START_DONE\n");
    }

    return true;
}

void npu_wq_task_proc(unsigned int core_id, taskElement *element)
{
    if (npu_start_wq_task(core_id, element)) {
        NPU_ERR("start NPU fail!");
    }

    return;
}

void npu_start_wq_next_task(unsigned int core_id)
{
    npu_get_wq_task(core_id);

    return;
}

void npu_wq_task_restore(unsigned int core_id)
{
    npu_get_wq_task(core_id);

    return;
}

int npu_push_wq_task(const void *arg, unsigned int irq_num)
{
    unsigned int core_id;
    taskElement element;
    NPU_SSWQ_TASK_ELEMENT_S task_element;

    memcpy_s((void *)&task_element, sizeof(NPU_SSWQ_TASK_ELEMENT_S), arg, sizeof(NPU_SSWQ_TASK_ELEMENT_S));
    core_id = task_element.core_id;
    if (0 != core_id) {
        NPU_ERR("Input parameter is error!core_id:%d", core_id);
        return -1;
    }

    if (!CHECK_TASK_TYPE(task_element.task_type)) {
        NPU_ERR("Input task_type is error!task_type:%d", task_element.task_type);
        return -1;
    }

    if (NPU_COMPUTE_TASK == task_element.task_type) {
        while (NPU_TASK_START_NONE != g_task_private.start_task[core_id].state) {
            //SRE_DelayMs(1);
            hmapi_yield();
        }
    } else {
        if (NPU_TASK_START_NONE == g_task_private.start_task[core_id].state) {
            NPU_ERR("Task Order Error!core_id:%d", core_id);
            return -1;
        }
    }

    element.taskType        = task_element.task_type;
    element.offchipInstAddr = task_element.inst_addr_off;
    element.offchipInstSize = task_element.inst_size;
    task_wq_private.boot_inst_set.npu_access_ddr_addr = task_element.ddr_base_addr >> 20;
    NPU_PRINT("\n push task:npu_access_ddr_addr:%d\n", task_wq_private.boot_inst_set.npu_access_ddr_addr);
    element.taskId          = task_element.task_id;
    element.prior           = task_element.task_priority;
    element.ptaskFlag       = NULL;/*Ensure point correct*/

    /*Caution : Already obtain task_fifo_sem !!*/
    SRE_HwiDisable(irq_num);
    npu_task_fifo_opt_lock(task_element.core_id);

    if (element.taskType != NPU_SYNC_TASK){
        memcpy_s(&g_task_private.start_task[core_id].start_element, sizeof(taskElement), &element, sizeof(taskElement));

        NPU_DEBUG("\n push task:start task \n");

        npu_wq_task_proc(core_id, &element);
    } else {
        NPU_PRINT("NPU_SYNC_TASK is waiting!");
        npu_task_fifo_opt_unlock(core_id);
        SRE_HwiEnable(irq_num);

        /* sync task sleeping */
        while (NPU_TASK_START_DONE != g_task_private.start_task[core_id].state){
            //SRE_DelayMs(1);
            hmapi_yield();
        };
        NPU_PRINT("-------up ok------\n");
        g_task_private.start_task[core_id].state = NPU_TASK_START_NONE;
        memset_s(&g_task_private.start_task[core_id].start_element, sizeof(taskElement), 0x0, sizeof(taskElement));

        return SUCCESS;
    }

    npu_task_fifo_opt_unlock(core_id);
    SRE_HwiEnable(irq_num);
    return SUCCESS;
}

