/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /******************************************************************************
 *
 *  The original Work has been changed by NXP Semiconductors.
 *
 *  Copyright (C) 2019 NXP Semiconductors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#ifndef __ESE_CONFIG_HISI_H__
#define __ESE_CONFIG_HISI_H__
#include <stdbool.h>

bool EseConfig_hasKey(unsigned int KEY);
unsigned int EseConfig_getUnsigned(unsigned int KEY);
const unsigned char * EseConfig_getString(unsigned int KEY, const unsigned char * defaultStr);

enum name
{
    NAME_NXP_TP_MEASUREMENT,
    NAME_NXP_NAD_POLL_RETRY_TIME,
    NAME_NXP_ESE_IFSD_VALUE,
    NAME_NXP_EUICC_IFSD_VALUE,
    NAME_NXP_SOF_WRITE,
    NAME_NXP_SPI_WRITE_TIMEOUT,
    NAME_NXP_P61_COLD_RESET_INTERFACE,
    NAME_NXP_WTX_COUNT_VALUE,
    NAME_RNACK_RETRY_DELAY,
    NAME_NXP_MAX_RNACK_RETRY,
    NAME_NXP_SPI_INTF_RST_ENABLE,
    NAME_NXP_POWER_SCHEME,
    NAME_NXP_VISO_DPD_ENABLED,
    NAME_NXP_P61_JCOP_DEFAULT_INTERFACE,
    NAME_NXP_ESE_DEV_NODE,
};

#endif /* __ESE_CONFIG_HISI_H__ */