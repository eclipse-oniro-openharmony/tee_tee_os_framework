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

#ifdef CONFIG_TEST_CA_CHECK
#include "tee_test_calist.h"
const char *g_teeos_testca_blacklist[] = {
    "tee_test",
    "teec_hello",
    "test_crypto",
    "test_huk",
    "test_ta",
    "test_hello",
    "test_tui",
    "crypto_modollized_test",
    "crypto_full_scale_test",
    "crl_ctrl_test",
    "tui-demoCA",
    "api_compatible_test",
    "crl_ctrl_agent",
    "tee_rollback_test"
};

const uint32_t g_teeos_testca_blacklist_num = sizeof(g_teeos_testca_blacklist) / sizeof(g_teeos_testca_blacklist[0]);

const char **get_testca_blacklist(void)
{
    return g_teeos_testca_blacklist;
}

uint32_t get_testca_blacklist_num(void)
{
    return g_teeos_testca_blacklist_num;
}
#endif
