/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: tee flash
 * Created: 2021-07-08
 */

#ifndef _TEE_FLASH_EXT_H
#define _TEE_FLASH_EXT_H

#ifdef __cplusplus
extern "C"
{
#endif

unsigned int ext_tee_flash_get_rpmb_info(void *addr, unsigned int size);
unsigned int ext_tee_flash_get_rpmb_key(void *addr, unsigned int size);
unsigned int ext_tee_flash_check_rpmb_key_status(void *addr, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif /* _TEE_API_RPMB_H */

