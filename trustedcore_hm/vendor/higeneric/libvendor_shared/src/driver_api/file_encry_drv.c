#include <stdint.h>
#include <hm_mman_ext.h>
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "sre_syscalls_ext.h"
#include "tee_internal_api.h"
#include "tee_log.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"
#ifdef TEE_SUPPORT_FILE_ENCRY

__attribute__((visibility("default"))) \
INT32 __file_encry_interface(INT32 cmd_id, UINT8 *iv_buf, UINT32 length)
{
    uint64_t args[] = {
        (uint64_t)cmd_id,
        (uint64_t)(uintptr_t)iv_buf, /* Not support 64bit TA */
        (uint64_t)length,
    };
    return hm_drv_call(SW_SYSCALL_FILE_ENCRY_INTERFACE, args, ARRAY_SIZE(args));
}
#endif
