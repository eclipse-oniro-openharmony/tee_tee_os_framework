/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: v3.1 ta config builder
 * Author: qishuai qishuai6@huawei.com
 * Create: 2022-02-07
 */

#ifndef TA_CONFIG_BUILDER_H
#define TA_CONFIG_BUILDER_H

#include <tee_defines.h>
#include "dyn_conf_dispatch_inf.h"

enum ta_config_tags {
    CONFIGINFO = 0x0,
    CONFIGINFO_TA_BASIC_INFO = 0x1,
    CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME,
    CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME_SERVICE_NAME,
    CONFIGINFO_TA_BASIC_INFO_UUID,
    CONFIGINFO_TA_BASIC_INFO_UUID_UUID,
    CONFIGINFO_TA_MANIFEST_INFO,
    CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE,
    CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE_INSTANCE_KEEP_ALIVE,
    CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE_STACK_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE_HEAP_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE,
    CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE_TARGET_TYPE,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND_MULTI_COMMAND,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION_MULTI_SESSION,
    CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE,
    CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE_SINGLE_INSTANCE,
    CONFIGINFO_TA_CONTROL_INFO,
#if (defined(CONFIG_APP_TEE_RPMB) || defined(CONFIG_APP_TEE_RPMB_A32))
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO,
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO_RPMB_SIZE,
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO_RPMB_SIZE_RPMB_SIZE,
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO_RPMB_PERMISSION,
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO_RPMB_PERMISSION_RPMB_GENERAL,
    CONFIGINFO_TA_CONTROL_INFO_RPMB_INFO_RPMB_PERMISSION_RPMB_GENERAL_RPMB_GENERAL,
#endif
#if defined(CONFIG_APP_TEE_SE)
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO,
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION,
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION_SE_OPEN_SESSION,
#endif
#if (defined(CONFIG_LIB_TUI) || defined(CONFIG_LIB_TUI_A32))
    CONFIGINFO_TA_CONTROL_INFO_TUI_INFO,
    CONFIGINFO_TA_CONTROL_INFO_TUI_INFO_TUI_GENERAL,
    CONFIGINFO_TA_CONTROL_INFO_TUI_INFO_TUI_GENERAL_TUI_GENERAL,
#endif
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS_DEBUG_STATUS,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID_DEBUG_DEVICE_ID,
    CONFIGINFO_UNUSED,
};

#define RPMB_GENERAL_PERMISSION      0x01U
#define RPMB_RESET_PERMISSION        0x04U
#define SE_OPEN_SESSION_PERMISSION   0x01U
#define TUI_PERMISSION               0x01U

/* CN format in TA's certificate: "uuid string" + "_" + "service name" */
#define TA_CERT_MAX_CN_INFO_LEN   64
#define TA_CERT_CN_UNDERLINE_SIZE 1
#define UUID_STR_LEN              36
#define TLV_DEVICE_ID_LEN         64U
#define POLICY_OLD_VERSION        0
#define POLICY_VERSION_ONE        1
#define MAX_CALLEE_TA_COUNT       100
#define MAX_CALLEE_COMMAND_COUNT  100
#define DEVICE_ID_LEN             32
#define LEN_OFFSET_VALUE          4U
#define MAX_SERVICE_NAME_LEN 40

struct ta_manifest_info {
    bool single_instance;
    bool multi_session;
    bool multi_command;
    bool instance_keep_alive;
    uint32_t heap_size;
    uint32_t stack_size;
    bool mem_page_align;
    uint32_t target_type;
};

struct ta_rpmb_info {
    uint32_t size;
    uint64_t permissions;
};

struct ta_sfs_info {
    uint64_t permissions;
};

struct ta_se_info {
    uint64_t permissions;
};

struct ta_tui_info {
    uint64_t permissions;
};

struct ta_debug_info {
    bool status;
    bool valid_device;
};

struct callee_ta_info {
    struct callee_ta_info *next;
    TEE_UUID uuid;
    uint32_t command_num;
    uint32_t *command_id;
};

struct ta_control_info {
    struct ta_rpmb_info rpmb_info;
    struct ta_sfs_info sfs_info;
    struct ta_se_info se_info;
    struct ta_tui_info tui_info;
    uint32_t ta_manager;
    struct callee_ta_info *callee_info;
    struct ta_debug_info debug_info;
};

struct config_info {
    struct list_head head;
    TEE_UUID uuid;
    char service_name[MAX_SERVICE_NAME_LEN];
    uint32_t service_name_len;
    uint32_t version;
    struct ta_manifest_info manifest_info;
    struct ta_control_info control_info;
};

int32_t install_ta_config(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue);
TEE_Result check_device_id(struct config_info *config, const uint8_t *buff, uint32_t len);

#endif
