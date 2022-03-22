/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: header of taload for ioctl.
 * Author: BSP group
 * Create: 2020-01-17
 */

#ifndef __DRV_TALOAD_IOCTL_H__
#define __DRV_TALOAD_IOCTL_H__

#include "hi_type_dev.h"
#include "hi_tee_module_id.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define TALOAD_RSA_PUBLIC_KEY_E_LEN     4
#define TALOAD_RSA_PUBLIC_KEY_N_LEN     256
#define TALOAD_IOC_NA                   0U
#define TALOAD_IOC_W                    1U
#define TALOAD_IOC_R                    2U
#define TALOAD_IOC_RW                   3U
#define taload_ioc(dir, type, nr, size) (((dir) << 30) | ((size) << 16) | ((type) << 8) | ((nr) << 0))
#define taload_ior(nr, size)            taload_ioc(TALOAD_IOC_R, HI_ID_TALOAD, (nr), size)

typedef struct {
    hi_u8 rsa_key_n[TALOAD_RSA_PUBLIC_KEY_N_LEN];
    hi_u8 rsa_key_e[TALOAD_RSA_PUBLIC_KEY_E_LEN];
} taload_rsa_key;

#define TALOAD_IOCTL_GET_ROOT_PUB_KEY             taload_ior(0x00, sizeof(taload_rsa_key))
#define TALOAD_IOCTL_GET_EXT_PUB_KEY              taload_ior(0x01, sizeof(taload_rsa_key))
#define TALOAD_IOCTL_GET_TAROOTCERT_DOUBLEL_SIGN  taload_ior(0x02, sizeof(taload_rsa_key))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* End of #ifndef __DRV_TALOAD_IOCTL_H__ */
