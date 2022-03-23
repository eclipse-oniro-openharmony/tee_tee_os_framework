/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: add wrapped keys for new platforms
 * Create: 2019-04
 */

#ifndef GTASK_ECIES_WRAPPED_H
#define GTASK_ECIES_WRAPPED_H

#include "ta_load_key.h"

#ifndef CONFIG_CDC

#include "ecies_wrapped_key_cs.h"

#else /* CONFIG_CDC */

#if defined(WITH_CHIP_CS2)
#include "ecies_wrapped_key_cs2_cdc.h"
#else
#include "ecies_wrapped_key_cs_cdc.h"
#endif

#endif /* CONFIG_CDC */

#endif
