/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef TEE_SKYTONE_API_H
#define TEE_SKYTONE_API_H

#include "tee_defines.h"

/*
 * @ingroup  TEE_EXT SKYTONE API
 * @brief  get skytone version
 *
 * @par
 *
 * @retval return the skytone version
 *
 *
 * @par dependence:
 * @li tee_ext_api.h
 * @see
 * @since V100R007C00
 */
uint32_t TEE_EXT_Get_Skytone_Version(void);
#endif
