/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto oemkey syscall
 * Create: 2022-01-13
 */
#include "crypto_syscall_oemkey.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <hmlog.h>
#include "drv_param_ops.h"

static int32_t get_oemkey_ops(const struct crypto_drv_ops_t *ops, struct memref_t *buf_arg)
{
    if (ops->get_oemkey == NULL) {
        hm_error("hardware engine get entropy fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    void *buffer = NULL;
    size_t size;

    buffer = (void *)(uintptr_t)buf_arg->buffer;
    size = buf_arg->size;

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->get_oemkey(buffer, size);
    if (ret != CRYPTO_SUCCESS)
        hm_error("get oemkey failed\n");

    do_power_off(ops);

    return ret;
}

int32_t get_oemkey_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = get_oemkey_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return CRYPTO_SUCCESS;
}
