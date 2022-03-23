/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2016-2018. All rights reserved.
 * Description: Chip definition and para check.
 */

#ifndef __TEE_DRV_COMMON_H__
#define __TEE_DRV_COMMON_H__

#include "hi_log.h"
#include "hi_type_dev.h"

#ifdef __cplusplus
extern "C" {
#endif

#define USECS_PER_SEC   1000000

/* Define the chip type. */
typedef enum {
    TEE_CHIP_TYPE_HI3716M,
    TEE_CHIP_TYPE_HI3716D,
    TEE_CHIP_TYPE_HI3796C    = 0x20,
    TEE_CHIP_TYPE_HI3798C,
    TEE_CHIP_TYPE_HI3796M,
    TEE_CHIP_TYPE_HI3798M,

    TEE_CHIP_TYPE_HI3796C_A  = 0x40,
    TEE_CHIP_TYPE_HI3798C_A,
    TEE_CHIP_TYPE_HI3798C_B,

    TEE_CHIP_TYPE_HI3798M_A,
    TEE_CHIP_TYPE_HI3798M_H,

    TEE_CHIP_TYPE_HI3751 = 0x80,

    TEE_CHIP_TYPE_MAX
} tee_chip_type;

/* Define the chip version. */
typedef enum {
    TEE_CHIP_VERSION_V100 = 0x100,
    TEE_CHIP_VERSION_V101 = 0x101,
    TEE_CHIP_VERSION_V110 = 0x110,
    TEE_CHIP_VERSION_V200 = 0x200,
    TEE_CHIP_VERSION_V210 = 0x210,
    TEE_CHIP_VERSION_V300 = 0x300,
    TEE_CHIP_VERSION_V310 = 0x310,
    TEE_CHIP_VERSION_V400 = 0x400,
    TEE_CHIP_VERSION_V410 = 0x410,
    TEE_CHIP_VERSION_V420 = 0x420,
    TEE_CHIP_VERSION_V450 = 0x450,
    TEE_CHIP_VERSION_V900 = 0x900,
    TEE_CHIP_VERSION_MAX
} tee_chip_version;

#define HI_TEE_RIGHTCHECK_W(val, size) do {           \
    if (!tee_hal_access_check(val, size)) {           \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
    if (!tee_hal_write_right_check(val, size)) {      \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
} while (0)

#define HI_TEE_RIGHTCHECK_R(val, size) do {           \
    if (!tee_hal_access_check(val, size)) {           \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
    if (!tee_hal_read_right_check(val, size)) {       \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
} while (0)

#define HI_TEE_RIGHTCHECK_RW(val, size) do {          \
    if (!tee_hal_access_check(val, size)) {           \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
    if (!tee_hal_write_right_check(val, size)) {      \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
    if (!tee_hal_read_right_check(val, size)) {       \
        hi_err_print_err_code(HI_TEE_ERR_NOPERMISSION); \
        return HI_TEE_ERR_NOPERMISSION;               \
    }                                                 \
} while (0)

#define COMMON_MEM_ACCESS_CHECK(addr, size) do {                     \
    if (!tee_hal_access_check((void *)(uintptr_t)addr, size)) {      \
        break;                                                       \
    }                                                                \
    if (!tee_hal_write_right_check((void *)(uintptr_t)addr, size)) { \
        break;                                                       \
    }                                                                \
} while (0)

hi_s32 hi_drv_common_delay_us(hi_u32 us);

hi_s32 hi_drv_common_get_chip_version(tee_chip_type *chip_type, tee_chip_version *chip_version);

#ifdef __cplusplus
}
#endif

#endif
