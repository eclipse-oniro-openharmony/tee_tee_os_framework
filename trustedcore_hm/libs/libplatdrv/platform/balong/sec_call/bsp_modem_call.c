/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#include <osl_balong.h>
#include <bsp_modem_call.h>
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include <drv_module.h>
#include <drv_pal.h>
#include "tee_log.h"

#define MODEM_CALL_IS_STUB   (0x901800ff)      /* 桩接口返回值 */
#define TA_TO_DRV_FUNC_MAX   (FUNC_TA_TO_DRV_MAX - FUNC_TA_TO_DRV_MIN)
#define CA_TO_DRV_FUNC_MAX   (FUNC_CA_TO_DRV_MAX - FUNC_CA_TO_DRV_MIN)
#define MODEM_CALL_FUNC_MAX  (TA_TO_DRV_FUNC_MAX + CA_TO_DRV_FUNC_MAX)

int (*modem_call_func[MODEM_CALL_FUNC_MAX])(unsigned int arg1, void *arg2, unsigned int arg3);

int bsp_modem_call_register(FUNC_CMD_ID call_id, MODEM_CALL_HOOK_FUNC modem_call)
{
    if ((call_id >= FUNC_TA_TO_DRV_MIN) && (call_id < FUNC_TA_TO_DRV_MAX)) {
        modem_call_func[call_id - FUNC_TA_TO_DRV_MIN] = modem_call;
    } else if ((call_id >= FUNC_CA_TO_DRV_MIN) && (call_id < FUNC_CA_TO_DRV_MAX)) {
        modem_call_func[(call_id - FUNC_CA_TO_DRV_MIN) + TA_TO_DRV_FUNC_MAX] = modem_call;
    } else {
        tloge("modem call register fail call_id: 0x%x\n", call_id);
        return -1;
    }
    return 0;
}

int bsp_modem_call(unsigned int func_cmd, unsigned int arg1, void *arg2, unsigned int arg3)
{
    int ret;
    FUNC_CMD_ID call_id;
    tloge("modem call func_cmd is : 0x%x\n", func_cmd);
    call_id = (FUNC_CMD_ID)func_cmd;
    if ((call_id >= FUNC_TA_TO_DRV_MIN) && (call_id < FUNC_TA_TO_DRV_MAX)) {
        call_id = call_id - FUNC_TA_TO_DRV_MIN;
    } else if ((call_id >= FUNC_CA_TO_DRV_MIN) && (call_id < FUNC_CA_TO_DRV_MAX)) {
        call_id = (call_id - FUNC_CA_TO_DRV_MIN) + TA_TO_DRV_FUNC_MAX;
    } else {
        tloge("error func_cmd: 0x%x\n", func_cmd);
        return -1;
    }

    if (modem_call_func[call_id] != NULL) {
        ret = modem_call_func[call_id](arg1, arg2, arg3);
        if (ret) {
            tloge("modem call func is failed: 0x%x\n", func_cmd);
        }
        return ret;
    } else {
        tloge("modem call func is null: 0x%x\n", func_cmd);
        return (int)MODEM_CALL_IS_STUB;
    }
}

#include <hmdrv_stub.h>

int sec_call_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    UINT32 uwRet = 0;
    /* According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them */
    if (!params || !params->args) {
        tloge("%s invalid input\n", __func__);
        return -1;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_BSP_MODEM_CALL, permissions, MDMCALL_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
        uwRet = (UINT32)bsp_modem_call((unsigned int)args[0], (unsigned int)args[1], (void *)(uintptr_t)args[2], (unsigned int)args[3]);
        args[0] = uwRet;
        SYSCALL_END

        default:
            return -1;
    }
    return 0;
}

DECLARE_TC_DRV(
        sec_call_driver,
        0,
        0,
        0,
        TC_DRV_MODULE_INIT,
        NULL,
        NULL,
        sec_call_syscall,
        NULL,
        NULL
        );

