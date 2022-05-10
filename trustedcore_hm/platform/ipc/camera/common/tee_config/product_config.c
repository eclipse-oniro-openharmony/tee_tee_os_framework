/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Create: 2020-07
 */

#include "tee_config.h"
#include "product_agent.h"
#include "product_uuid.h"

static const struct ext_agent_uuid_item g_ext_agent_whitelist[] = {
    { TEE_SERVICE_SECSCP, TEE_SECSCP_AGENT_ID },
};
static const uint32_t g_ext_agent_item_num = sizeof(g_ext_agent_whitelist) / sizeof(g_ext_agent_whitelist[0]);

const struct ext_agent_uuid_item *get_ext_agent_whitelist(void)
{
    return g_ext_agent_whitelist;
}

uint32_t get_ext_agent_item_num(void)
{
    return g_ext_agent_item_num;
}
