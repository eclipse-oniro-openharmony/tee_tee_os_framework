/* ************************************************************************** */
/*                                                                           */
/*                Copyright 2008 - 2050, Huawei Tech. Co., Ltd.              */
/*                           ALL RIGHTS RESERVED                             */
/*                                                                           */
/* ************************************************************************** */
#include <stdint.h>
#include <hm_mman_ext.h>
#include <hm_msg_type.h> // for ARRAY_SIZE

#include "lib_timer.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_internal_api.h"
#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"
#include <stdio.h>

/*
 * RTOSck integrated Secure Element API
 * in rtosck:
 *   __XXXX are used by el0 apps (e.g.: ta)
 *   XXXX are used by kernel (e.g.: drivers)
 * due to the drivers now are moved to el0, most apis we need to
 * provide two version.
 */

int __scard_connect(int reader_id, unsigned int vote_id,
                    void *p_atr, unsigned int *atr_len)
{
    if (!atr_len) {
        printf("__scard_connect: invalid args art_len is null\n");
        return -1;
    }
    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)vote_id,
        (uint64_t)(uintptr_t)p_atr, /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)atr_len, /* Not support 64bit TA now */
    };
    uint32_t lens[] = {
        0,
        0,
        0,
        sizeof(unsigned int)
    };
    return hm_drv_call_ex(SW_SYSCALL_SCARD_CONNECT, args, lens,
                          ARRAY_SIZE(args), NULL, 0);
}

int __scard_disconnect(int reader_id, unsigned int vote_id)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)vote_id,
    };
    return hm_drv_call(SW_SYSCALL_SCARD_DISCONNECT, args, ARRAY_SIZE(args));
}

int __driver_p61_factory_test(int reader_id)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
    };

    return hm_drv_call(SW_SYSCALL_P61_FAC_TEST, args, ARRAY_SIZE(args));
}

int __phNxpEse_GetOsMode(void)
{
    return hm_drv_call(SW_SYSCALL_ESE_GET_OS_MODE, NULL, 0);
}

int __ese_proto7816_reset(void)
{
	return hm_drv_call(SW_SYSCALL_ESE_7816_RESET, NULL, 0);
}

int __ese_set_nfc_chiptype(int chip_type)
{
    uint64_t args[] = {
        (uint64_t)chip_type,
    };

    return hm_drv_call(SW_SYSCALL_SET_NFC_TYPE, args, ARRAY_SIZE(args));
}

int __scard_transmit(int reader_id, unsigned char *p_cmd, unsigned int cmd_len,
                     unsigned char *p_rsp, unsigned int *rsp_len)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)(uintptr_t)p_cmd, /* Not support 64bit TA now */
        (uint64_t)cmd_len,
        (uint64_t)(uintptr_t)p_rsp, /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)rsp_len, /* Not support 64bit TA now */
    };
    uint32_t lens[] = {
        0,
        0,
        0,
        0,
        sizeof(unsigned int)
    };
    if (!rsp_len) {
        printf("__scard_transmit: invalid args, rsp_len is null\n");
        return -1;
    }

#ifdef CONFIG_FEATURE_SEPLAT
    return hm_drv_call_multithread_ex(SW_SYSCALL_SCARD_TRANSMIT, args, lens,
                                      ARRAY_SIZE(args), (void*)rsp_len,
                                      sizeof(unsigned int));
#else
    return hm_drv_call_ex(SW_SYSCALL_SCARD_TRANSMIT, args, lens,
                          ARRAY_SIZE(args), (void*)rsp_len,
                          sizeof(unsigned int));
#endif
}

int __scard_support_mode(int reader_id)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
    };

    return hm_drv_call(SW_SYSCALL_SCARD_SUPPORT_MODE, args, ARRAY_SIZE(args));
}

int __scard_send(int reader_id, unsigned char *p_cmd, unsigned int cmd_len)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)(uintptr_t)p_cmd, /* Not support 64bit TA now */
        (uint64_t)cmd_len,
    };
    uint32_t lens[] = { 0, 0, 0 };
    if (cmd_len < SYSCALL_DATA_MAX) {
        lens[1] = cmd_len;
    };
    return hm_drv_call_multithread_ex(SW_SYSCALL_SCARD_SEND, args, lens, ARRAY_SIZE(args), NULL, 0);
}

int __scard_receive(unsigned char *p_rsp, unsigned int *rsp_len)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_rsp,   /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)rsp_len, /* Not support 64bit TA now */
    };
    uint32_t lens[] = { 0, sizeof(unsigned int) };
    return hm_drv_call_multithread_ex(SW_SYSCALL_SCARD_RECEIVE, args, lens,
                                      ARRAY_SIZE(args), rsp_len, sizeof(unsigned int));
}

int __scard_get_status(void)
{
    return hm_drv_call(SW_SYSCALL_SCARD_GET_STATUS, NULL, 0);
}

int __inse_connect(void *id)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)id, /* Not support 64bit TA now */
    };
    uint32_t lens[] = { sizeof(unsigned int) };
    return hm_drv_call_ex(SW_SYSCALL_SE_CONNECT, args, lens, ARRAY_SIZE(args), NULL, 0);
}

int __inse_disconnect(void *id)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)id, /* Not support 64bit TA now */
    };

    uint32_t lens[] = { sizeof(unsigned int) };
    return hm_drv_call_ex(SW_SYSCALL_SE_DISCONNECT, args, lens, ARRAY_SIZE(args), NULL, 0);
}

int __ese_transmit_data(unsigned char *data, unsigned int data_size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)data, /* Not support 64bit TA now */
        (uint64_t)data_size,
    };
    return hm_drv_call(SW_SYSCALL_ESE_TRANSMIT, args, ARRAY_SIZE(args));
}

int __ese_read_data(unsigned char *data, unsigned int data_size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)data, /* Not support 64bit TA now */
        (uint64_t)data_size,
    };
    return hm_drv_call(SW_SYSCALL_ESE_READ, args, ARRAY_SIZE(args));
}

int __scard_get_ese_type(void)
{
    return hm_drv_call(SW_SYSCALL_SCARD_GET_ESE_TYPE, NULL, 0);
}

#ifdef FEATURE_SE
int __SE_getflag(void)
{
    return hm_drv_call(SW_SYSCALL_SE_GETFLAG, NULL, 0);
}

int __SE_setflag(int flag)
{
    uint64_t args[] = {
        (uint64_t)flag,
    };
    return hm_drv_call(SW_SYSCALL_SE_SETFLAG, args, ARRAY_SIZE(args));
}
#else
int __SE_getflag(void)
{
    return 0;
}

int __SE_setflag(int flag)
{
    (void)flag;
    return 0;
}
#endif
