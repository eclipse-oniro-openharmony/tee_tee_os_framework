/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto syscall cipher
 * Create: 2022-01-19
 */
#include "crypto_syscall_common.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <hmlog.h>
#include "drv_param_ops.h"

static int32_t cipher_init_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    struct crypto_ioctl *ioctl)
{
    if (ops->cipher_init == NULL) {
        hm_error("hardware engine cipher init fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    uint32_t driver_ability;
    uint32_t alg_type;

    driver_ability = ioctl->arg2;
    if ((driver_ability & DRIVER_PADDING) == DRIVER_PADDING)
        alg_type = ioctl->arg1;
    else
        alg_type = change_pkcs5_to_nopad(ioctl->arg1);

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *temp_crypto_arg = crypto_arg;
    void *ctx_buffer = alloc_and_fill_ctx_buf(temp_crypto_arg);
    if (ctx_buffer == NULL) {
        do_power_off(ops);
        return CRYPTO_OVERFLOW;
    }

    temp_crypto_arg++;
    struct symmerit_key_t key;
    key.key_type = ioctl->arg4;
    key.key_buffer = temp_crypto_arg->buffer;
    key.key_size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t iv;
    iv.buffer = temp_crypto_arg->buffer;
    iv.size = temp_crypto_arg->size;

    uint32_t direction = ioctl->arg3;
    ret = ops->cipher_init(alg_type, ctx_buffer, direction, &key, &iv);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do hmac init failed. ret = %d\n", ret);
        free(ctx_buffer);
        return ret;
    }

    (void)memcpy_s((void *)(uintptr_t)crypto_arg->buffer, crypto_arg->size, ctx_buffer, crypto_arg->size);
    free(ctx_buffer);
    return ret;
}

int32_t cipher_init_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_init_ops(ops, buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t cipher_update_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->cipher_update == NULL) {
        hm_error("hardware engine cipher update fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void *ctx_buffer = alloc_and_fill_ctx_buf(crypto_arg);
    if (ctx_buffer == NULL) {
        do_power_off(ops);
        return CRYPTO_OVERFLOW;
    }

    crypto_arg++;
    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->cipher_update(ctx_buffer, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do cipher update failed. ret = %d\n", ret);
        free(ctx_buffer);
        return ret;
    }

    crypto_arg--;
    if (data_out.size > crypto_arg->size) {
        hm_error("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        free(ctx_buffer);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    crypto_arg--;
    (void)memcpy_s((void *)(uintptr_t)crypto_arg->buffer, crypto_arg->size, ctx_buffer, crypto_arg->size);
    free(ctx_buffer);
    return ret;
}

int32_t cipher_update_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_update_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t cipher_dofinal_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->cipher_dofinal == NULL) {
        hm_error("hardware engine cipher dofinal fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void *ctx_buffer = alloc_and_fill_ctx_buf(crypto_arg);
    if (ctx_buffer == NULL) {
        do_power_off(ops);
        return CRYPTO_OVERFLOW;
    }

    crypto_arg++;
    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->cipher_dofinal(ctx_buffer, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do cipher dofinal failed. ret = %d\n", ret);
        free(ctx_buffer);
        return ret;
    }

    crypto_arg--;
    if (data_out.size > crypto_arg->size) {
        hm_error("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        free(ctx_buffer);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    crypto_arg--;
    (void)memcpy_s((void *)(uintptr_t)crypto_arg->buffer, crypto_arg->size, ctx_buffer, crypto_arg->size);
    free(ctx_buffer);
    return ret;
}

int32_t cipher_dofinal_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_dofinal_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t cipher_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    const struct crypto_ioctl *ioctl)
{
    if (ops->cipher == NULL) {
        hm_error("hardware engine cipher fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    uint32_t alg_type = ioctl->arg1;
    uint32_t direction = ioctl->arg2;
    struct memref_t *temp_crypto_arg = crypto_arg;

    struct memref_t data_out;
    data_out.buffer = temp_crypto_arg->buffer;
    data_out.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = temp_crypto_arg->buffer;
    data_in.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct symmerit_key_t key;
    key.key_type = ioctl->arg3;
    key.key_buffer = temp_crypto_arg->buffer;
    key.key_size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t iv;
    iv.buffer = temp_crypto_arg->buffer;
    iv.size = temp_crypto_arg->size;

    ret = ops->cipher(alg_type, direction, &key, &data_in, &data_out, &iv);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do cipher failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        hm_error("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    return ret;
}

int32_t cipher_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_ops(ops, buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
