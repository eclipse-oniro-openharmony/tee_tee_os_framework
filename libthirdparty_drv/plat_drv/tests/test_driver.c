#include <hisi_debug.h>
#include <tzpc.h>
#include <sre_sys.h>
#include <mem_page_ops.h>
#include <drv_module.h>
#include "lib_timer.h"
#include "./../dma/dma.h"
#include "sre_syscalls_id_ext.h"
#include "sre_access_control.h"

int driver_dep_test(void)
{
	printf("driver test success!\n");
	return 0;
}
#include <hmdrv_stub.h>
#define TEST_PERMISSION 0
#define TEST_DRV_MAP	1
int driver_test_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uret;
    uint64_t conf_perm;
    uint64_t default_perm;
	uintptr_t addr;
	size_t size;

    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	if (swi_id == SW_SYSCALL_DRIVER_TEST) {
        if (args[0] == TEST_PERMISSION) {
			conf_perm = GENERAL_GROUP_PERMISSION;
			default_perm = permissions;
			addr = 0x0;
			size = 0x0;
        } else if (args[0] == TEST_DRV_MAP){
			conf_perm = permissions;
			default_perm = GENERAL_GROUP_PERMISSION;
			addr = -1;
			size = -1;
		}
	}
	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_DRIVER_TEST, conf_perm, default_perm)
        ACCESS_CHECK_A64(addr, size)
        uret = (uint32_t)driver_dep_test();
        args[0] = uret;
		SYSCALL_END
	default:
		return -1;
	}
	return 0; /*lint !e438*/
}

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(
	driver_test_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	driver_test_syscall,
	NULL,
	NULL
);
/*lint +e528 -esym(528,*)*/
