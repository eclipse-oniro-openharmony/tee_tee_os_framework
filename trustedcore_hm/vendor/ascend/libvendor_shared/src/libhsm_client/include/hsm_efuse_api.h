/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: HSM efuse api function
 * Author: chenyao
 * Create: 2020-04-26
 */
#ifndef _HSM_EFUSE_API_H_
#define _HSM_EFUSE_API_H_

TEE_Result TEE_HSM_RIM_UpDate(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_size);
TEE_Result TEE_HSM_Power_On(uint32_t dev_id);
TEE_Result TEE_HSM_Power_Off(uint32_t dev_id);

#endif
