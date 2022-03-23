/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert unf layer implementation
 * Author: Hisilicon hisecurity team
 * Create: 2019-12-08
 */

#include "tee_cert.h"

#include <sys/ioctl.h>
#include <pthread.h>
#include "securec.h"
#include "hmdrv.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_time_api.h"
#include "tee_drv_cert_ioctl.h"

/* memory */
#define hi_malloc(x) (0 < (x) ? TEE_Malloc(x, 0) : HI_NULL)
#define hi_free(x) {if (HI_NULL != (x)) TEE_Free(x);}

/* lock */
#define mutex_lock(lock)   pthread_mutex_lock(lock);
#define mutex_unlock(lock) pthread_mutex_unlock(lock);

/* atomic */
typedef hi_s32 atomic_t;

#define atomic_inc(x)      __sync_add_and_fetch((x), 1);
#define atomic_dec(x)      __sync_sub_and_fetch((x), 1);
#define atomic_add(x, y)   __sync_add_and_fetch((x), (y))
#define atomic_sub(x, y)   __sync_sub_and_fetch((x), (y))
#define atomic_set(x, y)   __sync_lock_test_and_set((x), (y))
#define atomic_read(x)     __sync_add_and_fetch((x), 0)

/* golbal structure */
struct cert_initial {
    pthread_mutex_t            lock;

    atomic_t                   ref_count;
};

static struct cert_initial g_cert_initial = {
    .lock       = PTHREAD_MUTEX_INITIALIZER,
    .ref_count  = 0,
};

static hi_u8 *__swap(hi_u8 *data, hi_u32 len)
{
    hi_u8 *p = HI_NULL_PTR;
    hi_u8 *q = HI_NULL_PTR;
    hi_u8 b;

    if (len == 0) {
        return data;
    }
    for (p = data, q = data + len - 1; p < q; p++, q--) {
        b = *p;
        *p = *q;
        *q = b;
    }
    return data;
}

static hi_void __cert_swap_cmd(hi_cert_command *cmds)
{
    hi_u32 j;

    for (j = 0; j < DATA_NUM; j++) {
        __swap(&cmds->input_data[j * DATA_LEN], DATA_LEN);
        __swap(&cmds->output_data[j * DATA_LEN], DATA_LEN);
    }
    __swap(cmds->status, DATA_LEN);
    __swap(cmds->opcodes, DATA_LEN);
}

static hi_void __dump_data(const hi_cert_command *cert_data)
{
    hi_u32 i;
    hi_info_cert("-----input-----DUMP DATA:.\n--datain: \n");
    for (i = 0; i < REG_DATA_NUM; i++) {
        hi_info_cert("Write DI_%d :  %02x%02x%02x%02x\n", i,
                     cert_data->input_data[i * DATA_LEN + 0x0], cert_data->input_data[i * DATA_LEN + 0x1],
                     cert_data->input_data[i * DATA_LEN + 0x2], cert_data->input_data[i * DATA_LEN + 0x3]);
    }
    hi_info_cert("Write COM  :  %02x%02x%02x%02x\n",
                 cert_data->opcodes[0x0], cert_data->opcodes[0x1], cert_data->opcodes[0x2], cert_data->opcodes[0x3]);

    hi_info_cert("wait_done\n");
    for (i = 0; i < REG_DATA_NUM; i++) {
        hi_info_cert("Read DO_%d  :  %02x%02x%02x%02x\n", i,
                     cert_data->output_data[i * DATA_LEN + 0x0], cert_data->output_data[i * DATA_LEN + 0x1],
                     cert_data->output_data[i * DATA_LEN + 0x2], cert_data->output_data[i * DATA_LEN + 0x3]);
    }
    hi_info_cert("Read STA   :  %02x%02x%02x%02x\n",
                 cert_data->status[0x0], cert_data->status[0x1], cert_data->status[0x2], cert_data->status[0x3]);
}

struct cert_initial *__get_cert_initial(hi_void)
{
    return &g_cert_initial;
}

static hi_s32 __cert_ioctl(unsigned int cmd, hi_void *data)
{
    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)data,
    };

    return hm_drv_call(CMD_CERT_PROCESS, args, ARRAY_SIZE(args));
}

hi_s32 hi_mpi_cert_init(hi_void)
{
    struct cert_initial *initial = __get_cert_initial();

    cert_func_enter();
    mutex_lock(&initial->lock);

    if (atomic_read(&initial->ref_count) > 0) {
        atomic_inc(&initial->ref_count);
        goto out;
    }

    atomic_set(&initial->ref_count, 1);

out:
    mutex_unlock(&initial->lock);

    cert_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cert_deinit(hi_void)
{
    struct cert_initial *initial = __get_cert_initial();

    cert_func_enter();

    mutex_lock(&initial->lock);

    if (atomic_read(&initial->ref_count) > 0) {
        atomic_dec(&initial->ref_count);
    }

    if (atomic_read(&initial->ref_count) != 0) {
        goto out;
    }

    atomic_set(&initial->ref_count, -1);

out:
    mutex_unlock(&initial->lock);

    cert_func_exit();
    return HI_SUCCESS;
}

hi_s32 hi_mpi_cert_usekey(hi_cert_key_data *ctl_data)
{
    hi_s32 ret;

    cert_func_enter();
    if (ctl_data == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    ret = __cert_ioctl(CMD_CERT_AKLKEYSEND_CTL, ctl_data);
    if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_AKLKEYSEND_CTL, ctl_data), ret);
        goto out;
    }

    cert_func_exit();

out:
    return ret;
}

hi_s32 hi_mpi_cert_get_metadata(hi_u32 *metadata)
{
    hi_s32 ret;

    cert_func_enter();
    if (metadata == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    ret = __cert_ioctl(CMD_CERT_METADATA, metadata);
    if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_METADATA, metadata), ret);
        goto out;
    }

    cert_func_exit();

out:
    return ret;
}

hi_s32 hi_mpi_cert_reset(hi_void)
{
    hi_s32 ret;

    cert_func_enter();

    ret = __cert_ioctl(CMD_CERT_RESET, HI_NULL);
    if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_RESET), ret);
        goto out;
    }

    cert_func_exit();

out:
    return ret;
}

hi_s32 hi_mpi_cert_lock(hi_cert_res_handle **res_handle)
{
    hi_s32 ret;
    hi_cert_res_handle *handle = HI_NULL;

    cert_func_enter();

    if (res_handle == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    handle = hi_malloc(sizeof(hi_cert_res_handle));
    if (handle == HI_NULL) {
        ret = HI_ERR_KLAD_NO_MEMORY;
        goto out;
    }

    if (memset_s(handle, sizeof(hi_cert_res_handle), 0, sizeof(*handle)) != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }

    ret = __cert_ioctl(CMD_CERT_LOCK, handle);
    if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_LOCK, handle), ret);
        goto free;
    }

    hi_dbg_cert("Cert lock OK, res=%p, handle=%d\n", handle, handle->res_handle);
    *res_handle = (hi_cert_res_handle *)handle;

    cert_func_exit();
    return HI_SUCCESS;

free:
    hi_free(handle);
out:
    return ret;
}

hi_s32 hi_mpi_cert_unlock(hi_cert_res_handle *handle)
{
    hi_s32 ret;

    cert_func_enter();

    if (handle == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    ret = __cert_ioctl(CMD_CERT_UNLOCK, handle);
    if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_UNLOCK, handle), ret);
        goto out;
    }

    hi_free(handle);

    cert_func_exit();

out:
    return ret;
}

static hi_s32 __cert_exchange_process(hi_cert_res_handle *handle, hi_cert_command *command,
                                      hi_size_t *num_of_processed_commands)
{
    hi_s32 ret;
    cert_cmd_ctl ctl = {0};

    cert_func_enter();

    ctl.handle.res_handle = handle->res_handle;

    ret = memcpy_s(&ctl.cmd, sizeof(ctl.cmd), command, sizeof(hi_cert_command));
    if (ret != EOK) {
        return HI_ERR_KLAD_SEC_FAILED;
    }
    __cert_swap_cmd(&ctl.cmd);

    ret = __cert_ioctl(CMD_CERT_AKLEXCHANGE, &ctl);
    if (ret == HI_ERR_CERT_TIMEOUT) {
        __dump_data(command);
        print_err_func(__cert_ioctl(CMD_CERT_AKLEXCHANGE, &ctl), ret);
        return ret;
    } else if (ret != HI_SUCCESS) {
        print_err_func(__cert_ioctl(CMD_CERT_AKLEXCHANGE, &ctl), ret);
    }
    /* get data from driver, count increased. */
    __cert_swap_cmd(&ctl.cmd);
    ret = memcpy_s(command, sizeof(hi_cert_command), &ctl.cmd, sizeof(ctl.cmd));
    if (ret != EOK) {
        return HI_ERR_KLAD_SEC_FAILED;
    }
    *num_of_processed_commands = *num_of_processed_commands + 1;
    __dump_data(command);

    cert_func_exit();

    return ret;
}

hi_s32 hi_mpi_cert_exchange(hi_cert_res_handle *handle, hi_size_t num_of_commands,
                            hi_cert_command *command, hi_size_t *num_of_processed_commands)
{
    hi_size_t i;
    hi_s32 ret;

    cert_func_enter();

    if (command == HI_NULL || num_of_processed_commands == HI_NULL) {
        return HI_ERR_CERT_INVALID_PTR;
    }
    if ((num_of_commands < 1) || (num_of_commands > 0x100000)) {
        return HI_ERR_CERT_INVALID_PARA;
    }

    *num_of_processed_commands = 0;

    for (i = 0; i < num_of_commands; i++) {
        ret = __cert_exchange_process(handle, command + i, num_of_processed_commands);
        if (ret != HI_SUCCESS) {
            print_err_func(__cert_exchange_process, ret);
            return ret;
        }
    }

    *num_of_processed_commands = num_of_commands;
    cert_func_exit();
    return HI_SUCCESS;
}

