#include "bus_test.h"
#include <drv_mem.h>
#include "libhwsecurec/securec.h"
#include <drv_module.h>
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "drv_param_type.h"
#include <hmdrv_stub.h>
#include <tee_log.h>
#include <spi_test.h>
#include <i2c_test.h>
#include <i3c_test.h>

/* drv test function*/
typedef uint32_t (*bus_test_func)(uint32_t, const struct bus_test_para *);

/*ta to drv,drv test manage*/
struct bus_test_func_m {
	bus_test_func    test_func;
	char    *desc;
};

struct bus_test_func_m bus_test_func_tbl[] = {
	{ spi_driver_test,       "spi_driver_test" },
	{ i2c_driver_test,       "i2c_driver_test" },
	{ i3c_driver_test,       "i3c_driver_test" }
};

/*
 * @brief      : tee_call_hieps_drivers  ta-->teeos entry function
 * @param[in]  : parm_info, parm_size
 * @return     : 0: successful, -1: failed.
 * @note       : NA
 */
uint32_t tee_call_bus_drivers(
	const char *parm_info, uint32_t parm_size)
{
	uint32_t ret;
	uint32_t index;
	uint32_t parmnum;
	struct bus_test_para *pparm_info = NULL;
	char *pfunc_name = NULL;
	uint32_t count;

	pparm_info = (struct bus_test_para *)parm_info;
	if (pparm_info == NULL ||
		(parm_size != sizeof(struct bus_test_para))) {
		ret = BUS_TEEOS_ERROR;
		tloge("bus: parm error.\n");
		return ret;
	}

	parmnum = pparm_info->parm_num;
	if (parmnum > BUS_PARMNUM) {
		ret = BUS_TEEOS_ERROR;
		return ret;
	}
	pfunc_name = (char *)&(pparm_info->parm[0]);
	count = sizeof(bus_test_func_tbl) / sizeof(struct bus_test_func_m);

	for (index = 0; index < count; index++) {
		if (strncmp(bus_test_func_tbl[index].desc, pfunc_name,
			strlen(bus_test_func_tbl[index].desc) + 1) == 0) {
			if (bus_test_func_tbl[index].test_func) {
				ret = bus_test_func_tbl[index].test_func(
					parmnum - 1, pparm_info);
				return ret;
			}
			break;
		}
	}
	ret = BUS_CA_CMD_ERROR;
	return ret;
}

/*
 * @brief      :
 *
 * @param[in]  : swi_id: module id.
 * @param[in]  : params : parameter registers.
 * @param[in]  : permissions: access permission..
 *
 * @return     : 0: successful, -1: failed.
 */
int32_t bus_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t uw_ret = 0;

	if (!params || !params->args) {
		tloge("invalid input\n");
		return -1;
	}

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_LSBUS_DRV, permissions,
			GENERAL_GROUP_PERMISSION)
		if (args[2] > 0) {
			ACCESS_CHECK_A64(args[1], args[2]);
		} else {
			tloge("params err!\n");
			return -1;
		}
		ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
		ACCESS_WRITE_RIGHT_CHECK(args[1], args[2]);
		uw_ret = tee_call_bus_drivers(
				(char *)(uintptr_t)args[1],
				(uint32_t)args[2]);
		args[0] = uw_ret;
	SYSCALL_END

		default:
			return -1;
	}
	return 0;
}

/* declare bus_driver module */

DECLARE_TC_DRV(
	bus_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	bus_syscall,
	NULL,
	NULL
);
