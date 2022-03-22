/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ese dummy defines
 * Author: QiShuai qishuai@huawei.com
 * Create: 2020-08-09
 */

#include "se_hal.h"
#include "sre_debug.h"
#include "tee_log.h"
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "boot_sharedmem.h"
#include <memory.h>
#include "spi.h"
#include "t1.h"
#include "drv_module.h"
#include <hmdrv_stub.h>
#include "spi_common.h"

#define WEAK __attribute__((weak))
#define PARAM_NOT_USED(val) ((void)val)

#define SECFLASH_SCARD_READERID 2
#define ESE_READERID 1
#define INVALID_READERID_ERR (-1)
#define ESE_INFO_LEN 12
#define ESE_INFO_NFCTYPE_INDEX 10
#define NFCTYPE_INVALID 0
#define NFCTYPE_ST21NFC 1
#define NFCTYPE_NXP 2
#define NFCTYPE_SN110 3

#define INVALID_NOTSUPPORT (-1)
#define MEM_DATA_SIZE 8
#define ESE_MAGIC_NUM  0x66BB
#define OFFSET_8       8
#define OFFSET_16      16
#define RET_ERR (-1)
#define RET_SUC 0

typedef struct {
	u16 head_magic;
	u16 gpio_svdd_pwr_req;
	u8 spi_bus;
	u8 nfc_type;
	u16 resv[4];
	u16 tail_magic;
} __attribute__((__packed__))  ese_dts_conf;

ese_dts_conf g_ese_dts_conf;

int check_ese_magic()
{
	if ((ESE_MAGIC_NUM != g_ese_dts_conf.head_magic)
		|| (ESE_MAGIC_NUM != g_ese_dts_conf.tail_magic)) {
		tloge("check_ese_magic, maybe uninitialized or modified, head_magic 0x%x, tail_magic 0x%x\n",
			g_ese_dts_conf.head_magic, g_ese_dts_conf.tail_magic);
		return RET_ERR;
	}
	if (g_ese_dts_conf.spi_bus >= SPI_NUM) {
		tloge("spi_bus%d is invalid\n", g_ese_dts_conf.spi_bus);
		return RET_ERR;
	}
	return RET_SUC;
}

int load_ese_config(void)
{
	int ret;
	uint8_t shared_mem[MEM_DATA_SIZE];

	tloge("enter load_ese_config\n");
	if (check_ese_magic() == RET_SUC) {
		tloge("load_ese_config has been initialized\n");
		return RET_SUC;
	}
	/* clear ese dts config zero */
	(void)memset_s((void*)&g_ese_dts_conf, sizeof(g_ese_dts_conf), 0, sizeof(g_ese_dts_conf));

	/* map ese dts config ddr memory address */
	ret = (uint32_t)get_shared_mem_info(TEEOS_SHARED_MEM_ESE, (uint32_t *)shared_mem, sizeof(shared_mem));
	if (ret) {
		tloge("Get sharemem info Failed, ret is 0x%x.\n", ret);
		return RET_ERR;
	}
	hex_print_line((unsigned char *)shared_mem, sizeof(shared_mem));
	g_ese_dts_conf.nfc_type = shared_mem[0];
	g_ese_dts_conf.spi_bus = shared_mem[1];
	g_ese_dts_conf.head_magic = shared_mem[2] | (shared_mem[3] << OFFSET_8);
	g_ese_dts_conf.gpio_svdd_pwr_req = shared_mem[4] | (shared_mem[5] << OFFSET_8);
	g_ese_dts_conf.tail_magic = shared_mem[6] | (shared_mem[7] << OFFSET_8);

	tloge("get head_magic = 0x%x\n", g_ese_dts_conf.head_magic);
	tloge("get spi_bus = %d\n", g_ese_dts_conf.spi_bus);
	tloge("get gpio_svdd_pwr_req = %d\n", g_ese_dts_conf.gpio_svdd_pwr_req);
	tloge("get nfc_type = %d\n", g_ese_dts_conf.nfc_type);
	tloge("get tail_magic = 0x%x", g_ese_dts_conf.tail_magic);

	if (check_ese_magic() != RET_SUC) {
		tloge("load_ese_config sharemem is wrong\n");
		return RET_ERR;
	}
	if (init_ese_spi(g_ese_dts_conf.spi_bus) != 0) {
		(void)memset_s((void*)&g_ese_dts_conf, sizeof(g_ese_dts_conf),
			0, sizeof(g_ese_dts_conf));
		tloge("load_ese_config exit, init spi fail\n");
		return RET_ERR;
	}
	tloge("load_ese_config exit\n");
	return RET_SUC;
}

int scard_support_mode(int reader_id)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	return SCARD_MODE_SYNC;
}

int p61_factory_test(int reader_id)
{
	tloge("p61_factory_test enter\n");
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}

	tloge("[p61_factory_test]reader_id = %d, g_ese_dts_conf.nfc_type = %d.\n",
		reader_id, g_ese_dts_conf.nfc_type);
	if (g_ese_dts_conf.nfc_type == NFCTYPE_INVALID) {
		/* if g_ese_dts_conf.nfc_type is invalid */
		tloge("p61_factory_test invalid nfc_type\n");
		return RET_ERR;
	}
	tloge("[p61_factory_test]g_ese_dts_conf.nfc_type=%d.\n", g_ese_dts_conf.nfc_type);
	if (g_ese_dts_conf.nfc_type == NFCTYPE_ST21NFC) {
		return t1_factory_test();
	} else if (g_ese_dts_conf.nfc_type == NFCTYPE_SN110) {
		return p73_p61_factory_test();
	} else {
		tloge("p61_factory_test no support\n");
		return RET_ERR;
	}
}

int scard_connect(int reader_id, void *atr, unsigned int *atr_len)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	if (g_ese_dts_conf.nfc_type == NFCTYPE_INVALID) {
		/* if g_ese_dts_conf.nfc_type is invalid */
		tloge("scard_connect invalid nfc_type\n");
		return RET_ERR;
	}
	if (g_ese_dts_conf.nfc_type == NFCTYPE_ST21NFC) {
		return t1_scard_connect(reader_id, atr, atr_len);
	} else if (g_ese_dts_conf.nfc_type == NFCTYPE_SN110) {
		return p73_scard_connect(reader_id, atr, atr_len);
	} else {
		tloge("scard_connect no support\n");
		return RET_ERR;
	}
}

int scard_disconnect(int reader_id)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	if (g_ese_dts_conf.nfc_type == NFCTYPE_INVALID) {
		/* if g_ese_dts_conf.nfc_type is invalid */
		tloge("scard_disconnect invalid nfc_type\n");
		return RET_ERR;
	}
	if (g_ese_dts_conf.nfc_type == NFCTYPE_ST21NFC) {
		return t1_scard_disconnect(reader_id);
	} else if (g_ese_dts_conf.nfc_type == NFCTYPE_SN110) {
		return p73_scard_disconnect(reader_id);
	} else {
		tloge("scard_disconnect no support\n");
		return RET_ERR;
	}
}

int scard_transmit(int reader_id, unsigned char *cmd, unsigned int cmd_len,
	unsigned char *rsp, unsigned int *rsp_len)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}

	if (g_ese_dts_conf.nfc_type == NFCTYPE_INVALID) {
		/* if g_ese_dts_conf.nfc_type is invalid */
		tloge("scard_transmit invalid nfc_type\n");
		return RET_ERR;
	}
	if (g_ese_dts_conf.nfc_type == NFCTYPE_ST21NFC) {
		return t1_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
	} else if (g_ese_dts_conf.nfc_type == NFCTYPE_SN110) {
		return p73_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
	} else {
		tloge("scard_transmit no support\n");
		return RET_ERR;
	}
}

int scard_get_ese_type(void)
{
	int ret;
	ret = load_ese_config();
	if (ret != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	return 1;
}
WEAK int scard_send(int reader_id, unsigned char *cmd, unsigned int cmd_len)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	PARAM_NOT_USED(reader_id);
	PARAM_NOT_USED(cmd);
	PARAM_NOT_USED(cmd_len);
	tlogd("se dummy:scard send\n");
	return 0;
}

WEAK int scard_receive(unsigned char *rsp, unsigned int *rsp_len)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	PARAM_NOT_USED(rsp);
	PARAM_NOT_USED(rsp_len);
	tlogd("se dummy:scard receive\n");
	return 0;
}

WEAK int scard_get_status(void)
{
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	tlogd("se dummy:scard get status\n");
	return SCARD_STATUS_RECEIVE_NOT_READY;
}

WEAK int ese_transmit_data(unsigned char *data, unsigned int data_size)
{
	(void)data;
	(void)data_size;
	if (load_ese_config() != RET_SUC) {
		tloge("ese dts cofig or spi not initialized\n");
		return RET_ERR;
	}
	tloge("ese_transmit_data debug\n");
	return 0;
}

int scard_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	UINT32 uwRet = 0;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them */

	/* HMOS extended */
	char *data = (char *)(uintptr_t)params->data;
	char *rdata = (char *)(uintptr_t)params->rdata;
	size_t rdata_len = (size_t)params->rdata_len;

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    tloge("scard_syscall id %d\n", swi_id);
	HANDLE_SYSCALL(swi_id) {

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_CONNECT, permissions,
				   SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		if (args[2] != 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		args[2] = (uintptr_t)(data + args[2]);
		ACCESS_CHECK_A64(args[1], *((unsigned int *)(args[2])));
		ACCESS_WRITE_RIGHT_CHECK(args[1], *((unsigned int *)(args[2])));
		uwRet = (UINT32)scard_connect((int)args[0], (void *)args[1], (unsigned int *)args[2]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_DISCONNECT, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		uwRet = (UINT32)scard_disconnect((int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_TRANSMIT, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		if (args[4] != 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		args[4] = (UINT32)(data + args[4]);
		ACCESS_CHECK_A64(args[1], args[2]);
		ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
		if (args[4]) {
			ACCESS_CHECK_A64(args[3], *(unsigned int *)args[4]);
			ACCESS_WRITE_RIGHT_CHECK(args[3], *(unsigned int *)args[4]);
		}
		uwRet = (UINT32)scard_transmit((int)args[0], (unsigned char *)args[1], (unsigned int)args[2], (unsigned char *)args[3], (unsigned int *)args[4]);
		if (memcpy_s(rdata, rdata_len, (unsigned char *)args[4], sizeof(unsigned int))) {
			params->rdata_len = 0;
			args[0] = OS_ERROR;
		} else {
			params->rdata_len = sizeof(unsigned int);
			args[0] = uwRet;
		}
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_SUPPORT_MODE, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		uwRet = (UINT32)scard_support_mode((int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_SEND, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		if (args[2] >= SYSCALL_DATA_MAX) {
			ACCESS_CHECK_A64(args[1], args[2]);
			ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
		} else {
			if (args[1] != 0) {
				args[0] = OS_ERROR;
				goto out;
			}
			args[1] = (uintptr_t)(data + args[1]);
		}
		uwRet = (UINT32)scard_send((int)args[0], (unsigned char *)args[1], (unsigned int)args[2]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_RECEIVE, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		if (args[1] != 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		args[1] = (uintptr_t)(data + args[1]);
		if (args[1]) {
			   ACCESS_CHECK_A64(args[0], *(unsigned int *)args[1]);
			   ACCESS_WRITE_RIGHT_CHECK(args[0], *(unsigned int *)args[1]);
		}

		uwRet = (UINT32)scard_receive((unsigned char *)args[0], (unsigned int *)args[1]);
		if (memcpy_s(rdata, rdata_len, (unsigned char *)args[1], sizeof(unsigned int))) {
			rdata_len = 0;
			args[0] = OS_ERROR;
		} else {
			rdata_len = sizeof(unsigned int);
			args[0] = uwRet;
		}
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_GET_STATUS, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		uwRet = (UINT32)scard_get_status();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_P61_FAC_TEST, permissions,
				GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		uwRet = (UINT32)p61_factory_test((int)args[0]);
		args[0] = uwRet;
		SYSCALL_END


		SYSCALL_PERMISSION(SW_SYSCALL_ESE_TRANSMIT, permissions,
				GENERIC_SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		if (args[1]) {
			ACCESS_CHECK_A64(args[0], args[1]);
			ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
		}
		uwRet = (UINT32)ese_transmit_data((void *)args[0], args[1]);
		args[0] = uwRet;
		SYSCALL_END


		SYSCALL_PERMISSION(SW_SYSCALL_SCARD_GET_ESE_TYPE, permissions,
				SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
		uwRet = (UINT32)scard_get_ese_type();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_ESE_GET_OS_MODE, permissions,
				GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
#ifdef SE_SUPPORT_SN110
		uwRet = (uint32_t)GetOsMode();
		args[0] = uwRet;
#endif
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_ESE_7816_RESET, permissions,
				GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
#ifdef SE_SUPPORT_SN110
		uwRet = (uint32_t)p73_EseProto7816_Reset();
		args[0] = uwRet;
#endif
		SYSCALL_END

	default:
		return -1;
	}
	return 0;
}

DECLARE_TC_DRV(
	eSE,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	scard_syscall,
	NULL,
	NULL
);
