/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ipc test driver for MSP core.
 * Author : z00452790
 * Create: 2020/06/09
 */

#include <mspc_ipc_test.h>
#include <mspc_errno.h>
#include <tee_log.h>
#include <hmlog.h>
#include <se_hal.h>
#include <sre_sys.h>
#include <mspc_ipc.h>
#include <drv_mem.h>
#include <securec.h>

int32_t mspc_ipc_test(struct mspc_ipc_test_msg *msg_data)
{
    int32_t ret;
    struct mspc_ipc_msg msg;
    uint32_t i;

    if (!msg_data) {
        tloge("%s:Invalid input!\n", __func__);
        return MSPC_ERROR;
    }
    for (i = 0; i < sizeof(struct mspc_ipc_test_msg) / sizeof(uint32_t); i++)
        tloge("mspc: data%d = 0x%x\n", i, msg_data->data[i]);
    (void)memset_s(&msg, sizeof(struct mspc_ipc_msg),
                   0, sizeof(struct mspc_ipc_msg));
    ret = memcpy_s((void *)&(msg.data[MSPC_IPC_DATA0]), sizeof(msg.data),
                   (void *)msg_data, sizeof(struct mspc_ipc_test_msg));
    if (ret != EOK) {
        tloge("%s: memcpy_s err!\n", __func__);
        return MSPC_ERROR;
    }
    tloge("mspc: type = 0x%x, cmd = 0x%x, obj = 0x%x, src = 0x%x\n",
        msg.cmd_mix.cmd_type, msg.cmd_mix.cmd, msg.cmd_mix.cmd_obj, msg.cmd_mix.cmd_src);
    ret = mspc_send_ipc(OBJ_MSPC, &msg, MSPC_ASYNC_MODE);
    if (ret != MSPC_OK)
        tloge("%s: mspc ipc test fail\n", __func__);
    else
        tloge("%s: mspc ipc test success\n", __func__);

    return ret;
}

int32_t mspc_ddr_read(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *buff_len)
{
    int32_t ret;
    uint32_t addr_va;
    uint32_t i;
    uint8_t *paddr = NULL;

    if (!buff || !buff_len || *buff_len < len || addr < MSPC_DDR_TEST_START ||
        len > MSPC_DDR_TEST_SIZE || addr + len > MSPC_DDR_TEST_START + MSPC_DDR_TEST_SIZE) {
        tloge("%s: param error \n", __func__);
        return MSPC_ERROR;
    }
    ret = sre_mmap(addr, len, (unsigned int *)(uintptr_t)&addr_va, secure, non_cache);
    if (ret != 0) {
        tloge("%s: addr map fail\n", __func__);
        return MSPC_ERROR;
    }
    paddr = (uintptr_t)addr_va;
    for (i = 0; i < len; i++) {
        buff[i] = read_byte(paddr);
        paddr++;
    }

    *buff_len = i;
    (void)sre_unmap(addr_va, len);
    tloge("mspc: ddr read success\n");

    return MSPC_OK;
}

int32_t mspc_ddr_write(uint8_t *buff, uint32_t buff_len, uint32_t addr)
{
    int32_t ret;
    uint32_t addr_va;
    uint32_t i;
    uint8_t *paddr = NULL;

    if (!buff || addr < MSPC_DDR_TEST_START || buff_len > MSPC_DDR_TEST_SIZE ||
        addr + buff_len > MSPC_DDR_TEST_START + MSPC_DDR_TEST_SIZE) {
        tloge("%s: param error \n", __func__);
        return MSPC_ERROR;
    }
    ret = sre_mmap(addr, buff_len, (unsigned int *)(uintptr_t)&addr_va, secure, non_cache);
    if (ret != 0) {
        tloge("%s: addr map fail\n", __func__);
        return MSPC_ERROR;
    }
    paddr = (uintptr_t)addr_va;
    for (i = 0; i < buff_len; i++) {
        write_byte(paddr, buff[i]);
        paddr++;
    }

    (void)sre_unmap(addr_va, buff_len);
    tloge("mspc: ddr write success\n");

    return MSPC_OK;
}
