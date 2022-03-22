/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * File Name: tee_api_ssm.c
 * Description: ssm
 * Author: Hisilicon
 * Created: 2019-07-08
 */

#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_ssm.h"
#include "hi_type_dev.h"

hi_s32 hi_tee_ssm_create(hi_tee_ssm_intent intent, hi_handle *addr)
{
    unsigned int args[] = {
        (unsigned int)intent,
        (unsigned int)(uintptr_t)addr
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_CREATE, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_destroy(hi_handle target_handle)
{
    unsigned int args[] = {
        (unsigned int)target_handle
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_DESTROY, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_add_resource(hi_handle session_handle, hi_tee_ssm_module_info *mod_info_addr)
{
    unsigned int args[] = {
        (unsigned int)session_handle,
        (unsigned int)(uintptr_t)mod_info_addr
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_ADD_RESOURCE, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_attach_buffer(hi_tee_ssm_buffer_attach_info *attach_info_addr, hi_u64 *sec_info_addr)
{
    unsigned int args[] = {
        (unsigned int)(uintptr_t)attach_info_addr,
        (unsigned int)(uintptr_t)sec_info_addr
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_ATTACH_BUF, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_get_intent(hi_handle session_handle, hi_tee_ssm_intent *intent_addr)
{
    unsigned int args[] = {
        (unsigned int)session_handle,
        (unsigned int)(uintptr_t)intent_addr
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_GET_INTENT, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_set_uuid(hi_handle session_handle)
{
    unsigned int args[] = {
        (unsigned int)session_handle
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_SET_UUID, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_check_uuid(hi_handle session_handle)
{
    unsigned int args[] = {
        (unsigned int)session_handle
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_CHECK_UUID, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_check_buf(const hi_tee_ssm_buffer_check_info *check_info)
{
    unsigned int args[] = {
        (unsigned int)(uintptr_t)check_info
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_CHECK_BUF, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_set_iommu_tag(hi_tee_logic_mod_id module_id)
{
    unsigned int args[] = {
        (unsigned int)module_id
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_IOMMU_CONFIG, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_send_policy_table(hi_handle session_handle, hi_tee_ssm_policy_table *policy_tbl)
{
    unsigned int args[] = {
        (unsigned int)session_handle,
        (unsigned int)(uintptr_t)policy_tbl
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_SEND_POLICY, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_init()
{
    unsigned int args[1] = {0};

    return hm_drv_call(HI_TEE_SYSCALL_SSM_INIT, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_ssm_set_reg(hi_u32 addr, hi_u32 val)
{
    unsigned int args[] = {
        (unsigned int)addr,
        (unsigned int)val
    };
    return hm_drv_call(HI_TEE_SYSCALL_SSM_SET_REG, args, ARRAY_SIZE(args));
}
