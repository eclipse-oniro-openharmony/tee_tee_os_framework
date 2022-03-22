#include "sre_typedef.h"
#include "drv_pal.h"
#include "drv_module.h"
#include "se_hal.h"
#include "tee_log.h"
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"
#include "hisi_debug.h"
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
#include "boot_sharedmem.h"
#include <memory.h>
#include "t1.h"
#endif
#ifdef SE_SUPPORT_SN110
#include "phNxpEse_Api_hisi.h"
#include "phNxpEse_Api_hisi_p61.h"
#endif
#include "hisee.h"
#include "p61.h"
#include "ese_data_handle.h"
#include "securec.h"

#ifdef CONFIG_HISI_SECFLASH
#include "secflash_data_link.h"
#endif
#ifdef CONFIG_HISI_MSPC
#include "mspc_api.h"
#endif
#ifdef CONFIG_FEATURE_SEPLAT_GP
#include "seplat_data_link.h"
#endif

#include "drv_param_type.h"

#define WEAK __attribute__((weak))
#define PARAM_NOT_USED(val) ((void)val)

#define INVALID_READERID_ERR        (-1)
#define ESE_INFO_LEN 15
#define ESE_INFO_NFCTYPE_INDEX      10
#define ESE_INFO_NFC_CHIPTYPE_INDEX 11
#define ESE_NFCSUPPROTED_INDEX      12
#define NFCTYPE_INVALID             0
#define NFCTYPE_ST21NFC             1
#define NFCTYPE_NXP                 2
#define NFCTYPE_SN110  3
#define NFC_NOT_LOADED 0
#define NFC_HAS_LOADED 1
#define NFC_BOTH_ESE_SUPPORT 1
#define NFC_BOTH_ESE_NOSUPPORT 0
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
uint32_t g_chooseNfcType = NFCTYPE_INVALID;
uint32_t g_nfcLoad = NFC_NOT_LOADED;
uint32_t g_bothEseSupport = NFC_BOTH_ESE_NOSUPPORT;
#endif

enum scard_read_id_type {
        INSE_READER_ID        = 0,
        ESE_READER_ID         = 1,
        SECFLASH_READER_ID    = 2,
        MSP_CORE_READER_ID    = 3,
};

#ifdef CONFIG_HISI_SECFLASH
static int scard_init(void)
{
	uint32_t ret = secflash_init(NULL);

	if (ret != SECFLASH_RET_SUCCESS)
		HISI_PRINT_ERROR("%s:%d, %08x\n", __func__, __LINE__, ret);

	return SRE_OK;
}

static int scard_suspend(void)
{
	uint32_t ret = secflash_power_save();

	if (ret != SECFLASH_RET_SUCCESS)
		HISI_PRINT_ERROR("%s:%d, %08x\n", __func__, __LINE__, ret);

	return SRE_OK;
}

static int scard_resume(void)
{
	/* NOTE do nothing */
	return SRE_OK;
}
#endif

#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
void load_config(void)
{
    uint32_t ese_info_arr[ESE_INFO_LEN];
    int i = 0;

    (void)memset_s(ese_info_arr, ESE_INFO_LEN * sizeof(uint32_t),
                   0, ESE_INFO_LEN * sizeof(uint32_t));

    if (get_shared_mem_info(TEEOS_SHARED_MEM_ESE, ese_info_arr, ESE_INFO_LEN * sizeof(uint32_t))) {
        HISI_PRINT_ERROR("load_config map tmp_ese_arr failed\n");
        return;
    }

    HISI_PRINT_ERROR("[load_config]ese_info_arr=%d.\n", ese_info_arr);

    for (i = 0; i < ESE_INFO_LEN; i++) {
        if (0xffffffff != ese_info_arr[i]) {
            break;
        }
    }

    if (ESE_INFO_LEN == i) {
        HISI_PRINT_ERROR("[load_config]get all ff value. means ese_init error!\n");
        return;
    }

    if (g_chooseNfcType == NFCTYPE_INVALID) {
        HISI_PRINT_ERROR("[load_config] g_chooseNfcType Invalid!\n");
        g_bothEseSupport = (unsigned int)ese_info_arr[ESE_NFCSUPPROTED_INDEX];
        g_chooseNfcType = (unsigned int)ese_info_arr[ESE_INFO_NFC_CHIPTYPE_INDEX];
    } else {
        g_nfcLoad = NFC_HAS_LOADED;
    }

    HISI_PRINT_ERROR("[load_config] g_nfcLoad = %d, g_bothEseSupport=%d, g_chooseNfcType=%d.\n",
        g_nfcLoad, g_bothEseSupport, g_chooseNfcType);
    return;
}
#endif

int scard_support_mode(int reader_id)
{
    if (reader_id == ESE_READER_ID)
        return SCARD_MODE_SYNC;
#ifdef CONFIG_HISI_SECFLASH
    else if (reader_id == SECFLASH_READER_ID)
        return SCARD_MODE_SYNC;
#endif
#ifdef CONFIG_FEATURE_SEPLAT_GP
    else if (reader_id == MSP_CORE_READER_ID)
        return SCARD_MODE_SYNC;
#endif
    else
#if(TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
        return SCARD_MODE_SYNC2;
#else
        return INVALID_READERID_ERR;
#endif
}

int scard_set_chiptype(int chip_type)
{
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
    g_chooseNfcType = chip_type;
    HISI_PRINT_ERROR("[scard_set_chiptype]g_nfcChipType=%d.\n", g_chooseNfcType);
#else
    PARAM_NOT_USED(chip_type);
#endif
    return 0;
}

int p61_factory_test(int chip_type)
{
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
    HISI_PRINT_ERROR("[p61_factory_test] chip_type=%d.\n",
        chip_type);

    if (chip_type == NFCTYPE_ST21NFC) {
        return t1_factory_test();
#ifdef SE_SUPPORT_SN110
    } else if (chip_type == NFCTYPE_SN110) {
        return p73_p61_factory_test();
#endif
    } else {
        return p61_p61_factory_test();
    }
#else
    PARAM_NOT_USED(chip_type);
    return p61_p61_factory_test();
#endif
}

int scard_connect(int reader_id, unsigned int vote_id,
                  void *atr, unsigned int *atr_len)
{
#ifdef CONFIG_HISI_MSPC
    int32_t ret;
#else
    PARAM_NOT_USED(vote_id);
#endif

    switch (reader_id) {
#if defined(CONFIG_HISI_MSPC) || defined(CONFIG_FEATURE_SEPLAT_GP)
    case MSP_CORE_READER_ID:
#ifdef CONFIG_FEATURE_SEPLAT_GP
            PARAM_NOT_USED(ret);
            PARAM_NOT_USED(vote_id);
            return SRE_OK;
#else
            ret = mspc_connect(vote_id, atr, atr_len);
            if (ret == MSPC_OK)
                ret = SRE_OK;
            return ret;
#endif
#else /* CONFIG_HISI_MSPC */
    case INSE_READER_ID:
#ifndef CONFIG_ESE_TEE2ATF_LOCK
        return hisee_scard_connect(reader_id, atr, atr_len);
#else
        return INVALID_READERID_ERR;
#endif
#endif /* CONFIG_HISI_MSPC */
#ifdef CONFIG_HISI_SECFLASH
    case SECFLASH_READER_ID:
        return SRE_OK;
#endif
    case ESE_READER_ID:
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
        if (g_nfcLoad == NFC_NOT_LOADED) {
            /* if g_chooseNfcType is invalid then set g_chooseNfcType value */
            load_config();
        }
#ifdef SE_SUPPORT_SN110
        if (g_bothEseSupport == NFC_BOTH_ESE_SUPPORT) {
            int result;
            /* now only support ST and SN110 both config */
            HISI_PRINT_ERROR("%s: Both P73 and t1 connect", __func__);
            result = p73_scard_connect(reader_id, atr, atr_len);
            g_chooseNfcType = NFCTYPE_SN110;
            if (result != 0) {
                result = t1_scard_connect(reader_id, atr, atr_len);
                g_chooseNfcType = NFCTYPE_ST21NFC;
            }
            g_nfcLoad = NFC_HAS_LOADED;
            return result;
        }
#endif
        if (g_chooseNfcType == NFCTYPE_ST21NFC) {
            return t1_scard_connect(reader_id, atr, atr_len);
    #ifdef SE_SUPPORT_SN110
        } else if (g_chooseNfcType == NFCTYPE_SN110) {
            return p73_scard_connect(reader_id, atr, atr_len);
    #endif
        } else {
            return p61_scard_connect(reader_id, atr, atr_len);
        }
#else
        return p61_scard_connect(reader_id, atr, atr_len);
#endif
    default:
        tloge("%s:Invalid reader id:%d\n", __func__, reader_id);
        return INVALID_READERID_ERR;
    }
}

int scard_disconnect(int reader_id, unsigned int vote_id)
{
#ifdef CONFIG_HISI_MSPC
    int32_t ret;
#else
    PARAM_NOT_USED(vote_id);
#endif

    switch (reader_id) {
#if defined(CONFIG_HISI_MSPC) || defined(CONFIG_FEATURE_SEPLAT_GP)
    case MSP_CORE_READER_ID:
#ifdef CONFIG_FEATURE_SEPLAT_GP
            PARAM_NOT_USED(ret);
            PARAM_NOT_USED(vote_id);
            return SRE_OK;
#else
            ret = mspc_disconnect(vote_id);
            if (ret == MSPC_OK)
                ret = SRE_OK;
            return ret;
#endif
#else /* CONFIG_HISI_MSPC */
    case INSE_READER_ID:
#ifndef CONFIG_ESE_TEE2ATF_LOCK
		return hisee_scard_disconnect(reader_id);
#else
		return INVALID_READERID_ERR;
#endif
#endif /* CONFIG_HISI_MSPC */
#ifdef CONFIG_HISI_SECFLASH
    case SECFLASH_READER_ID:
            return SRE_OK;
#endif
    case ESE_READER_ID:
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
        if (g_nfcLoad == NFC_NOT_LOADED) {
            /* if g_chooseNfcType is invalid then set g_chooseNfcType value */
            load_config();
        }
#ifdef SE_SUPPORT_SN110
        if (g_bothEseSupport == NFC_BOTH_ESE_SUPPORT) {
            int result;
            HISI_PRINT_ERROR("%s: Both P73 and t1 disconnect", __func__);
            result = p73_scard_disconnect(reader_id);
            if (g_chooseNfcType == NFCTYPE_ST21NFC) {
                result = t1_scard_disconnect(reader_id);
            }
            return result;
        }
#endif
        if (g_chooseNfcType == NFCTYPE_ST21NFC) {
            return t1_scard_disconnect(reader_id);
    #ifdef SE_SUPPORT_SN110
        } else if (g_chooseNfcType == NFCTYPE_SN110) {
            return p73_scard_disconnect(reader_id);
    #endif
        } else {
            return p61_scard_disconnect(reader_id);
        }
#else
        return p61_scard_disconnect(reader_id);
#endif
    default:
        tloge("%s:Invalid reader id:%d\n", __func__, reader_id);
        return INVALID_READERID_ERR;
    }
}

int scard_transmit(int reader_id, unsigned char *cmd, unsigned int cmd_len,
    unsigned char *rsp, unsigned int *rsp_len)
{
    if (reader_id == 0) {
        return 0;  /* 0: ok */
    }
#ifdef CONFIG_HISI_SECFLASH
    else if (reader_id == SECFLASH_READER_ID) {
        /* just pass the parameters, func secflash_transceive will check them */
        return secflash_transceive(cmd, cmd_len, cmd_len, rsp, *rsp_len, rsp_len);
    }
#endif
#ifdef CONFIG_FEATURE_SEPLAT_GP
    else if (reader_id == MSP_CORE_READER_ID) {
        if (!rsp_len)
            return OS_ERROR;
        return seplat_data_trans(cmd, cmd_len, rsp, *rsp_len, rsp_len);
    }
#endif
    else if (reader_id == ESE_READER_ID) {
#if defined(SE_SUPPORT_ST) || defined(SE_SUPPORT_MULTISE)
        if (g_nfcLoad == NFC_NOT_LOADED) {
            /* if g_chooseNfcType is invalid then set g_chooseNfcType value */
            load_config();
        }
        if (g_chooseNfcType == NFCTYPE_ST21NFC) {
            return t1_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
#ifdef SE_SUPPORT_SN110
        } else if (g_chooseNfcType == NFCTYPE_SN110) {
            return p73_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
#endif
        } else {
            return p61_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
        }
#else
        return p61_scard_transmit(reader_id, cmd, cmd_len, rsp, rsp_len);
#endif
    } else {
        return INVALID_READERID_ERR;
    }
}

WEAK int scard_send(int reader_id, unsigned char *cmd, unsigned int cmd_len)
{
	PARAM_NOT_USED(reader_id);
	PARAM_NOT_USED(cmd);
	PARAM_NOT_USED(cmd_len);
	tlogd("se dummy:scard send\n");
	return 0;
}

WEAK int scard_receive(unsigned char *rsp, unsigned int *rsp_len)
{
	PARAM_NOT_USED(rsp);
	PARAM_NOT_USED(rsp_len);
	tlogd("se dummy:scard receive\n");
	return 0;
}

WEAK int scard_get_status(void)
{
	tlogd("se dummy:scard get status\n");
	return SCARD_STATUS_RECEIVE_NOT_READY;
}

#include <hmdrv_stub.h>
int scard_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uwRet = 0;

    if (!params || !params->args) {
        tloge("%s invalid input\n", __func__);
        return -1;
    }

    /* HMOS extended */
    char *data = (char *)(uintptr_t)params->data;
    char *rdata = (char *)(uintptr_t)params->rdata;
    size_t rdata_len = (size_t)params->rdata_len;
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

    HANDLE_SYSCALL(swi_id) {
#ifndef CONFIG_ESE_EXCLUDE_P61
        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_CONNECT, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[3] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[3] = (uint64_t)(uintptr_t)data + args[3];
        ACCESS_CHECK_A64(args[2], *((unsigned int *)(uintptr_t)args[3]));
        ACCESS_WRITE_RIGHT_CHECK(args[1], *((unsigned int *)(uintptr_t)args[2]));
        uwRet = (uint32_t)scard_connect(
                        (int)args[0], (unsigned int)args[1],
                        (void *)(uintptr_t)args[2],
                        (unsigned int *)(uintptr_t)args[3]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_DISCONNECT, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)scard_disconnect((int)args[0], (unsigned int)args[1]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_TRANSMIT, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[4] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[4] = (uint64_t)(uintptr_t)data + args[4];
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        if (args[4]) {
            ACCESS_CHECK_A64(args[3], *(unsigned int *)(uintptr_t)args[4]);
            ACCESS_WRITE_RIGHT_CHECK(args[3], *(unsigned int *)(uintptr_t)args[4]);
        }
        uwRet = (uint32_t)scard_transmit(
                    (int)args[0],
                    (unsigned char *)(uintptr_t)args[1],
                    (unsigned int)args[2],
                    (unsigned char *)(uintptr_t)args[3],
                    (unsigned int *)(uintptr_t)args[4]);

        if (memcpy_s(rdata, rdata_len, (unsigned char *)(uintptr_t)args[4],
                     sizeof(unsigned int))) {
            params->rdata_len = 0;
            args[0] = OS_ERROR;
        } else {
            params->rdata_len = sizeof(unsigned int);
            args[0] = uwRet;
        }
        SYSCALL_END
#endif
        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_SUPPORT_MODE, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)scard_support_mode((int)args[0]);
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
            args[1] = (uint64_t)(uintptr_t)data + args[1];
        }
        uwRet = (uint32_t)scard_send(
                (int)args[0], (unsigned char *)(uintptr_t)args[1],
                (unsigned int)args[2]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_RECEIVE, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[1] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[1] = (uint64_t)(uintptr_t)data + args[1];
        if (args[1]) {
            ACCESS_CHECK_A64(args[0], *(unsigned int *)(uintptr_t)args[1]);
            ACCESS_WRITE_RIGHT_CHECK(args[0], *(unsigned int *)(uintptr_t)args[1]);
        }

        uwRet = (uint32_t)scard_receive(
                    (unsigned char *)(uintptr_t)args[0],
                    (unsigned int *)(uintptr_t)args[1]);
        if (memcpy_s(rdata, rdata_len, (unsigned char *)(uintptr_t)args[1],
                     sizeof(unsigned int))) {
            params->rdata_len = 0;
            args[0] = OS_ERROR;
        } else {
            params->rdata_len = sizeof(unsigned int);
            args[0] = uwRet;
        }
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_GET_STATUS, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)scard_get_status();
        args[0] = uwRet;
        SYSCALL_END

#ifndef CONFIG_ESE_EXCLUDE_P61
        SYSCALL_PERMISSION(SW_SYSCALL_P61_FAC_TEST, permissions,
                           GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)p61_factory_test((int)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SET_NFC_TYPE, permissions,
                           GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)scard_set_chiptype((int)args[0]);
        args[0] = uwRet;
        SYSCALL_END
#endif
#if !defined(CONFIG_ESE_TEE2ATF_LOCK) && !defined(CONFIG_HISI_MSPC)
        SYSCALL_PERMISSION(SW_SYSCALL_SE_CONNECT, permissions,
                           GENERIC_SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[0] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[0] = (uint64_t)(uintptr_t)data + args[0];
        uwRet = (uint32_t)inse_connect((void *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SE_DISCONNECT, permissions,
                           GENERIC_SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[0] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[0] = (uint64_t)(uintptr_t)data + args[0];
        uwRet = (uint32_t)inse_disconnect((void *)(uintptr_t)args[0]);
        args[0] = uwRet;
        SYSCALL_END
#endif /* CONFIG_ESE_TEE2ATF_LOCK and CONFIG_HISI_MSPC */
        SYSCALL_PERMISSION(SW_SYSCALL_ESE_TRANSMIT, permissions,
                           GENERIC_SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[1]) {
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        }
        uwRet = (uint32_t)ese_transmit_data((void *)(uintptr_t)args[0], args[1]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_ESE_READ, permissions,
                           GENERIC_SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[1]) {
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        }
        uwRet = (uint32_t)ese_read_data((void *)(uintptr_t)args[0], args[1]);
        args[0] = uwRet;
        SYSCALL_END
#ifndef CONFIG_ESE_EXCLUDE_P61
        SYSCALL_PERMISSION(SW_SYSCALL_SCARD_GET_ESE_TYPE, permissions,
                           SE_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)scard_get_ese_type();
        args[0] = uwRet;
        SYSCALL_END
#endif
        SYSCALL_PERMISSION(SW_SYSCALL_ESE_GET_OS_MODE, permissions,
                           GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
#ifdef SE_SUPPORT_SN110
        uwRet = (uint32_t)GetOsMode();
        args[0] = uwRet;
#endif
        SYSCALL_END
#ifdef CONFIG_HISI_SECFLASH
        SYSCALL_PERMISSION(SW_SYSCALL_SECFLASH_RESET, permissions,
                           SECFLASH_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        if (args[0] != SECFLASH_RESET_TYPE_SOFT &&
            args[0] != SECFLASH_RESET_TYPE_HARD) {
            args[0] = OS_ERROR;
            goto out;
        }
        uwRet = (uint32_t)secflash_chip_reset((int)args[0]);
        args[0] = uwRet;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECFLASH_POWER_SAVE, permissions,
                           SECFLASH_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        uwRet = (uint32_t)secflash_power_save();
        args[0] = uwRet;
        SYSCALL_END
#endif
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

DECLARE_TC_DRV_MULTI(
    eSE,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
#ifdef CONFIG_HISI_SECFLASH
    scard_init,
#elif CONFIG_FEATURE_SEPLAT_GP
    seplat_data_link_init,
#else
    NULL,
#endif
    NULL,
    scard_syscall,
#ifdef CONFIG_HISI_SECFLASH
    scard_suspend,
    scard_resume
#else
    NULL,
    NULL
#endif
);
