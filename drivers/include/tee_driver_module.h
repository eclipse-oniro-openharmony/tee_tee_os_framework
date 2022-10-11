/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: tee driver module structure, export to driver developer
 * Create: 2021-03-01
 */
#ifndef TEE_DRIVER_MODULE_H
#define TEE_DRIVER_MODULE_H
#include <stdint.h>
#include <tee_defines.h>

#define DRV_NAME_MAX_LEN 32U
#define DRV_RESERVED_NUM 8U

struct drv_data {
    int32_t fd; /* unique label which alloced by driver framework */
    uint32_t taskid; /* caller taskid */
    void *private_data; /* the private data associated with this fd */
    struct tee_uuid uuid; /* caller uuid */
};

typedef int32_t (*init_func)(void);

typedef int32_t (*suspned_func)(void);
typedef int32_t (*resume_func)(void);

typedef int64_t (*ioctl_func)(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len);
typedef int64_t (*open_func)(struct drv_data *drv, unsigned long args, uint32_t args_len);
typedef int64_t (*close_func)(struct drv_data *drv);

struct tee_driver_module {
    init_func init;
    ioctl_func ioctl;
    open_func open;
    close_func close;
    suspned_func suspend;
    resume_func resume;
    suspned_func suspend_s4;
    resume_func resume_s4;
    uint64_t reserved[DRV_RESERVED_NUM]; /* has not used, just reserved */
};

#define tee_driver_declare(name, init, open, ioctl, close, suspend, resume, suspend_s4, resume_s4) \
__attribute__((visibility("default"))) const struct tee_driver_module g_driver_##name = { \
    init, ioctl, open, close, suspend, resume, suspend_s4, resume_s4, {0} }

#endif /* TEE_DRIVER_MODULE_H */
