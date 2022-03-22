/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: sec api for platdrv
* Author: zhanglinhao zhanglinhao@huawei.com
* Create: 2020-10
*/

#include "sec_api.h"
#include <securec.h>
#include <drv_module.h>
#include <sre_access_control.h>
#include <drv_mem.h>
#include <tee_log.h>
#include <hmdrv_stub.h>
#include <register_ops.h>
#include <sre_syscalls_id.h>
#include "mem_ops.h"
#include "sec_ioaddr.h"
#include "acc_common.h"
#include "hi_sec_dlv.h"
#include "crypto_driver_adaptor.h"
#include "hi_sec_atest_api.h"
#include "acc_common_isr.h"

uint32_t g_sec_operating_status = 0;
struct acc_device *g_sec_dev = NULL;

static uint32_t g_sec_vf_num = 0;
static uint32_t g_sec_endian = 0;
static uint32_t g_sq_num = 2;

int sec_soft_reset_by_func(void)
{
    struct acc_device *sec_dev;

    sec_dev = g_sec_dev;
    return sec_soft_reset(sec_dev);
}

int sec_engine_init_by_func(void)
{
    struct acc_device *sec_dev;

    sec_dev = g_sec_dev;
    return sec_engine_init(sec_dev);
}

static struct qm_func_ops sec_ops = {
    .task_complete_proc = sec_task_complete_proc,
    .task_fault_proc = sec_task_fault_proc,
    .get_tag_field = sec_get_tag_field,
    .set_tag_field = sec_set_tag_field,
    .soft_reset = sec_soft_reset_by_func,
    .engine_init = sec_engine_init_by_func,
};

uint32_t sec_init(void)
{
    g_sec_operating_status = 1;
    struct acc_device *sec_dev;
    struct acc_hw_device_data *hw_data;
    uint32_t ret = SEC_FAIL;
    uint32_t tmp_sec_ctrl;

    sec_dev = (struct acc_device *)malloc(sizeof(*sec_dev));
    if (sec_dev == NULL) {
        tloge("alloc failed for sec dev mem!\n");
        return ret;
    }
    g_sec_dev = sec_dev;

    hw_data = (struct acc_hw_device_data *)malloc(sizeof(*hw_data));
    if (hw_data == NULL) {
        tloge("alloc failed for hardware data!\n");
        free(sec_dev);
        return ret;
    }

    sec_dev->hw_device = hw_data;
    acc_init_hw_data_sec(sec_dev->hw_device);

    hw_data->base_addr = 0x141800000;
    hw_data->subctrl_addr = 0x140070000;
    hw_data->peh_addr = PEH_PF_REGS_BASE_ADDR;

    sec_dev->num_vfs = g_sec_vf_num;
    sec_dev->sq_num = g_sq_num;
    sec_dev->endian = g_sec_endian;

    /* Set the sec mode to the security mode. */
    tmp_sec_ctrl = readl(hw_data->subctrl_addr + 0x20D0);
    write32(hw_data->subctrl_addr + 0x20D0, 0x1);
    tmp_sec_ctrl =  readl(hw_data->subctrl_addr + 0x20D0);
    if (!(tmp_sec_ctrl & 0x1)) {
        tloge("sec device init error, ret = 0x%x\n", ret);
        goto error;
    }

    ret = acc_dev_init(sec_dev);
    if (ret != 0) {
        tloge("sec device init error, ret = 0x%x\n", ret);
        goto error;
    }

    ret = hw_data->init_vf(sec_dev, &sec_ops);
    if (ret != 0) {
        tloge("sec init vf error, ret = 0x%x\n", ret);
        goto error;
    }

    tloge("sec init success!\n");

    g_sec_operating_status = 0;

    return SEC_SUCCESS;
error:
    g_sec_operating_status = 0;
    free(hw_data);
    free(sec_dev);
    return SEC_FAIL;
}

void sec_print_bd(struct sec_bd *bd)
{
    uint32_t i;

    tloge("sec bd:\n");
    for (i = 0; i < (SEC_BD_SIZE / sizeof(uint32_t)); i++)
        tloge("Word[%d]: 0x%x\n", i, bd->data[i]);
}

void sec_sm_callback(void *arg, struct sec_bd *p_bd)
{
    uint32_t result;

    result = (p_bd->data[28] >> 16) & 0xff;
    if (result == 0) {
        tlogi("bd return success\n");
    } else {
        tloge("bd return fail!\n");
        sec_print_bd(p_bd);
    }

    result = p_bd->data[28];
    *(uint32_t *)arg = result;

    return;
}

uint32_t sec_huk_pbkdf2(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    int ret, ret2;
    uint64_t phy_addr;
    struct hisi_sec_sqe bd;
    uint32_t bd_result = 0;
    uint8_t priority = 0;
    int type = 1;

    uint8_t *src_ptr;
    uint8_t *out_ptr;
    struct acc_device *sec_dev;

    if (derive_type) {
        tlogd("derive_type is %d\n", derive_type);
    }

    sec_dev = g_sec_dev;
    if (sec_dev == NULL) {
        tloge("error! sec device is NULL\n");
        return -1;
    }

    src_ptr = (uint8_t *)malloc_coherent(data_in->size);
    if(src_ptr == NULL) {
        tloge("src malloc failed!\n");
        return -1;
    }
    (void)memcpy_s(src_ptr , data_in->size, (void *)data_in->buffer, data_in->size);

    out_ptr = (uint8_t *)malloc_coherent(data_out->size);
    if(out_ptr == NULL) {
        tloge("out malloc failed!\n");
        return -1;
    }
    memset_s(out_ptr, data_out->size, 0x0, data_out->size);
    memset_s(&bd, sizeof(bd), 0x0, sizeof(bd));

    bd.type = 0x2;
    bd.auth = 0x1;
    bd.scene = 0x8;
    bd.type2.huk = 1;
    bd.type2.mac_len = 0x8;
    bd.type2.a_key_len = 0x8;
    bd.type2.a_alg = 0x11;
    bd.type2.a_len = data_in->size;
    bd.type2.c_len = 10000;
    bd.type2.pass_word_len = 0x20;
    bd.type2.dk_len = data_out->size;
    phy_addr = virt_mem_to_phys((uintptr_t)src_ptr);
    bd.type2.data_src_addr_l = (uint32_t)(phy_addr & GENMASK(31, 0));
    bd.type2.data_src_addr_h = phy_addr >> 32;

    phy_addr = virt_mem_to_phys((uintptr_t)out_ptr);

    // 18 19是MAC addr  密钥派生 实际做的是HMAC 最后输出是派生密钥就是计算得出的MAC值.
    bd.type2.mac_addr_l = (uint32_t)(phy_addr & GENMASK(31, 0));
    bd.type2.mac_addr_h = phy_addr >> 32;

    ret = sec_get_available_type_sq(type, &priority);
    if (ret != 0) {
        tloge("sec fail to get available sq for type = 1\n");
        bd_result = -1;
    }
    asm volatile("dsb sy");

    ret = sec_send_bd((struct hisi_sec_sqe *)&bd, priority, type);
    asm volatile("dsb sy");
    SRE_SwMsleep(5);

    ret2 = qm_eq_process(&g_sec_dev->qm_func);
    if (ret2) {
        tloge("qm_eq_process failed, ret = %d\n", ret2);
        return ret2;
    }
    asm volatile("dsb sy");

    struct sec_bd *sbd = (struct sec_bd *)(sec_dev->qm_func.sq[1].virt_addr + sec_dev->qm_func.sq[1].last_tail * sec_dev->qm_func.sqe_size);
    bd_result = sbd->data[28] & 0xffff;
    if (bd_result == 0x81) {
        bd_result = 0;
    } else {
        tloge("Sha256 result DE BD[28] 0x%x != 0x81\n", bd_result);
    }

    if (ret)
        bd_result = 1;

    asm volatile("dsb sy");
    acc_common_put_session(&sec_dev->qm_func, session_id);

    memcpy_s((void *)data_out->buffer, data_out->size, (void *)out_ptr, data_out->size);

    free(src_ptr);
    free(out_ptr);

    if (bd_result)
        return -1;
    else
        return 0;
}

int32_t sec_suspend(void)
{
    return 0;
}

int32_t sec_resume(void)
{
    return 0;
}
