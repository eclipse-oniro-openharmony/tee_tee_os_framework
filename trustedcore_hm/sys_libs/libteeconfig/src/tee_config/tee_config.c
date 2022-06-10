/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos platform configs
 * Create: 2020-03-20
 */
#include "tee_config.h"
#include <ac.h>
#include <security_ops.h>
#include <sys/hm_priorities.h> /* for HM_PRIO_TEE_* */
#include "tee_test_uuid.h"
#include "sre_access_control.h"

static struct drv_frame_info g_drv_frame_configs[] = {
#if defined(TEE_SUPPORT_PLATDRV_64BIT) || defined(TEE_SUPPORT_PLATDRV_32BIT)
    { "platdrv", AC_SID_PLATDRV, 0, TASKMAP2TASK_J, 0, 0, TEE_SERVICE_PLATDRV, true },
    { "multidrv", AC_SID_PLATDRV, 0, TASKMAP2TASK_J, 0, 0, TEE_SERVICE_PLATDRV, false },
#endif
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { "tee_drv_server", AC_SID_TEE_DRV_SERVER, 0, TASKMAP2TASK_J, 0, 0, TEE_DRV_SERVER, true },
    { "tee_drv_server_multi", AC_SID_TEE_DRV_SERVER, 0, TASKMAP2TASK_J, 0, 0, TEE_DRV_SERVER, false },
#endif
};

const uint32_t g_drv_frame_num = sizeof(g_drv_frame_configs) / sizeof(g_drv_frame_configs[0]);

uint32_t get_drv_frame_nums(void)
{
    return g_drv_frame_num;
}

struct drv_frame_info *get_drv_frame_infos(void)
{
    return g_drv_frame_configs;
}

/*
 * die_size is dependent on platforms index defined in plat.mk
 * WITH_XXX_PLATFORM
 * when new platforms added here, the array should be modefied
 * THIS SEQUENCE SHOULD NOT BE MODEFIED
 */
static const uint32_t g_die_id_size[] = { OTHER_DIE_ID_SIZE,
                                          M_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE };

static const uint32_t g_die_id_size_num = sizeof(g_die_id_size) / sizeof(g_die_id_size[0]);

uint32_t get_die_id_size_num(void)
{
    return g_die_id_size_num;
}

const uint32_t *get_tee_die_id_size(void)
{
    return g_die_id_size;
}

const struct ta_permission g_teeos_ta_permission_config[] = {
    { TEE_SERVICE_REET, 0, SMC_GROUP_PERMISSION },
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
    { TEE_SERVICE_HUK, 0, GENERAL_GROUP_PERMISSION | CC_KEY_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION},
#endif
#if (defined TEE_SUPPORT_PERM_64BIT || defined TEE_SUPPORT_PERM_32BIT)
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
#endif
};

static const uint32_t g_teeos_ta_permission_num =
    sizeof(g_teeos_ta_permission_config) / sizeof(g_teeos_ta_permission_config[0]);

uint32_t get_teeos_ta_permission_num(void)
{
    return g_teeos_ta_permission_num;
}

const struct ta_permission *get_teeos_ta_permission_config(void)
{
    return g_teeos_ta_permission_config;
}
