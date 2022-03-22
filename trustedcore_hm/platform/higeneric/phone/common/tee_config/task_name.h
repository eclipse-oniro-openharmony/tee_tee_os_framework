/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: task name declare
 * Create: 2020-02-19
 */
#ifndef PRODUCT_TASK_NAME_H
#define PRODUCT_TASK_NAME_H

#define GATEKEEPER_TASK_NAME     "task_gatekeeper"
#define KEYMASTER_TASK_NAME      "task_keymaster"
#define SECBOOT_TASK_NAME        "task_secboot"
#define SENSORINFO_TASK_NAME     "task_sensorinfo"
#define FINGERPRINT_TASK_NAME    "task_fingerprint"
#define KDS_TASK_NAME            "task_kds"
#define ANTIROOT_TASK_NAME       "task_antiroot"
#define STORAGE_TASK_NAME        "task_storage"
#define HIVCODEC_TASK_NAME       "task_hivcodec"
#define HIVCODEC_SR_TASK_NAME    "task_hivcodec_sr"
#define VDEC_TASK_NAME           "task_vdec"
#define SECMEM_TASK_NAME         "secmem"
#define SECISP_TASK_NAME         "task_secisp"
#define FILE_ENCRY_TASK_NAME     "task_file_encry"
#define BDKERNEL_TASK_NAME       "task_bdkernel"
#define ATTESTATION_TA_TASK_NAME "task_attestation_ta"
#define HWSDP_TASK_NAME          "task_hwsdp"

#ifdef DEF_ENG
#define TEST_SRV_TASK_NAME       "ut_task"
#define ECHO_TASK_NAME           "echo_task"
#define HMTEST_TASK_NAME         "hm-teeos-test"
#define TEST_INNER_TA_TASK_NAME  "test_inner_ta"
#define TEST_SERVICE_TASK_NAME   "test_service"
#define TEST_INNER_TA_TASK_NAME_A64  "test_inner_ta_a64"
#define TEST_SERVICE_TASK_NAME_A64   "test_service_a64"
#endif

#endif
