/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: task name declare
 * Author: wangzhuochen wangzhuochen1@huawei.com
 * Create: 2020-02-19
 */
#ifndef PRODUCT_TASK_NAME_H
#define PRODUCT_TASK_NAME_H

#define HSM_BBOX_NAME            "task_hsmbbox_ta"
#define KMS_TASK_NAME            "task_kms"
#define HSM_UPGRADE_NAME         "task_hsmupgrade_ta"
#define HSM_RPMBKEY_NAME         "task_rpmbkey_ta"
#define HSM_EFUSE_NAME           "task_efuse_ta"
#define HSM_FLASH_NAME           "task_flash_ta"

#ifdef DEF_ENG
#define TEST_SRV_TASK_NAME       "ut_task"
#define ECHO_TASK_NAME           "echo_task"
#define HMTEST_TASK_NAME         "hm-teeos-test"
#endif

#endif
