/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:Header file for seplat API.
 * Create: 2021/01/03
 */

#ifndef SEPLAT_API_H
#define SEPLAT_API_H

#include <tee_internal_api.h>
#include <stdint.h>

TEE_Result TEE_EXT_SEPLATIsAvailable(void);
TEE_Result TEE_EXT_SEPLATPowerOn(uint32_t vote_id);
TEE_Result TEE_EXT_SEPLATPowerOff(uint32_t vote_id);
TEE_Result TEE_EXT_SEPLATReset(uint32_t vote_id, uint32_t op_type);

#endif /* SEPLAT_API_H */
