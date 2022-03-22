#include <stdint.h>
#include <hm_mman_ext.h>
#include "lib_timer.h"
#include "sre_syscall.h"
#include "sre_syscalls_ext.h"
#include "tee_internal_api.h"
#include "tee_log.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"

unsigned int __npu_syscall_ioctl_cmdproc(void *command_info)
{
    if (command_info == NULL)
        return -1;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)command_info /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_NPU_IOCTL_CFG, args, ARRAY_SIZE(args));
}

unsigned int __npu_syscall_llseek_cmdproc(void *command_info)
{
    if (command_info == NULL)
        return -1;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)command_info /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_NPU_LLSEEK_CFG, args, ARRAY_SIZE(args));
}

unsigned int __npu_syscall_open_cmdproc(void)
{
    return hm_drv_call(SW_SYSCALL_NPU_OPEN_MODE_CFG, NULL, 0);
}

unsigned int __npu_syscall_release_cmdproc(void *command_info)
{
    if (command_info == NULL)
        return -1;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)command_info /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_NPU_REALEASE_MODE_CFG, args, ARRAY_SIZE(args));
}

unsigned int __npu_syscall_write_cmdproc(void *command_info)
{
    if (command_info == NULL)
        return -1;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)command_info /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_NPU_WRITE_INSTR_CFG, args, ARRAY_SIZE(args));
}

#ifdef TEE_SUPPORT_SVM
int __teesvm_ioctl(int svm_ta_tag, void *mcl)
{
    uint64_t args[] = {
        (uint64_t)svm_ta_tag,
        (uint64_t)mcl,
    };
    return hm_drv_call(SW_SYSCALL_NPU_SMMU_SVM, args, ARRAY_SIZE(args));
}
#endif
