/*******************************************************************************
 * @file       : sensorhub_ipc
 *
 * @brief      : platdrv in TEE for TA sending msg to sensorhub through ipc_s
 *
 * @date       : 2018.9.12
 *
 * @func       :
                DECLARE_TC_DRV@ declare drv handle
                sensorhub_ipc_init@ drv init
                sensorhub_ipc_syscall@ TA syscall func, including but not
                    limited to LOAD/UNLOAD/RUN/QUERY
                sensorhub_ipc_syscall_dispatch@ syscall dispatch
                sensorhub_ipc_send_data@ download payload to sensorhub
                sensorhub_ipc_send_msg_with_ack@ mbox operation
                sensorhub_ipc_wait_for_resp@ thread for waitin response
                sensorhub_ipc_query_ack@ upload result to TA
*******************************************************************************/
#include <sys/usrsyscall_ext.h>
#include <register_ops.h>
#include <sched.h>
#include <drv_pal.h>
#include <drv_module.h>
#include <sre_typedef.h> // UINT32
#include <ipc.h>
#include <dynion.h>
#include "tee_log.h"
#include "sre_syscalls_id_ext.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"
#include "securec.h"
#include "pthread.h"
#include "sensorhub_ipc.h"
#include "sre_hwi.h"
#include "secmem.h"
#include "sec_region_ops.h"
#include "hisi_secboot_external.h"

//
#define MIN(a, b)    ((a)<(b)?(a):(b))
//
#define CONTEXTHUB_HEADER_SIZE (sizeof(pkt_header_t) + sizeof(UINT32))
#define MAX_PKT_LENGTH         (128)
#define MAX_SEND_LEN           (32)
#define NO_RESP                (0)
#define TAG_SENSORHUB          (0x97)
#define TAG_END                (0xFF)
#define CMD_CMN_CONFIG_REQ     (7)
#define TIMEOUT_INIT           (10000)

//err handle
#define ASSERT_TIMEOUT(time, stat) \
    do{ \
        if(time == 0) {\
            tloge("[%s]:%d timeout failed! mbox state is 0x%x.\n", __func__, __LINE__, stat); \
            return ERR_TIMEOUT; \
        } \
    }while(0)
#define ASSERT_LOCK(ret) \
    do{ \
        if(ret != ERR_NONE) {\
            tloge("[%s]:%d lock operation failed! ret = %d.\n", __func__, __LINE__, ret); \
            return ret; \
        } \
    }while(0)
#define ASSERT_LOCK_RETURN_VOID(ret) \
    do{ \
        if(ret != ERR_NONE) {\
            tloge("[%s]:%d lock operation failed! ret = %d.\n", __func__, __LINE__, ret); \
            return; \
        } \
    }while(0)

//response buf lock
static pthread_mutex_t g_resp_buf_lock;
//response buf
enum {
    SH_NO_MSG = 0,
    SH_RESP_MSG = 1,
};
static UINT32 sensorhub_ipc_resp[IPC_DATA_REG_NUM] = {0};

const int VRL_HEAD_LENGTH = 1024 * 4; // vrl encryption head is 4K
static UINT32 VrlDecryption(UINT32 addr, UINT32 length)
{
    char vrlName[] = "npu_model";
    UINT32 ret = secboot_verify((paddr_t)(addr), VRL_HEAD_LENGTH,(paddr_t)(addr + VRL_HEAD_LENGTH),
        length - VRL_HEAD_LENGTH, vrlName, sizeof(vrlName));
    if (ret != 0) {
        tloge("tiny model vrl decryption error, ret = %d\n", ret);
    }
    return ret;
}

static UINT32 dcryptModel(void* payload, UINT32 length)
{
    msg_decrypt *msg = NULL;
    UINT32 safefd;
    UINT32 model_size;
    UINT32 ion_size;
    if (length < sizeof(msg_decrypt)) {
        tloge("[dcryptModel] payload length error!\n");
        return ERR_INVALID_MSG_LENGTH;
    }
    msg = (msg_decrypt *)payload;
    model_size = msg->modelsize;
    ion_size = msg->ionsize;
    safefd = msg->safefd;
    tloge("[dcryptModel] safefd:%d, %d, %d!\n", safefd, model_size, ion_size);
    const UINT32 va = sion_mmap_sfd(safefd, ion_size, DDR_SEC_TINY, 0, 1, 0);
    if (VrlDecryption(va, model_size) != 0) {
        tloge("[dcryptModel] VrlDecryption return error!\n");
        (void)sion_munmap_sfd(safefd, va, ion_size, DDR_SEC_TINY, 0, 0);
        return ERR_INVALID_POINTER;
    }
    (void)sion_munmap_sfd(safefd, va, ion_size, DDR_SEC_TINY, 0, 0);

    return ERR_NONE;
}

static UINT32 convert_sfd_to_sddr(void* payload, UINT32 length)
{
    UINT32 sfd;
    struct sglist *sg = NULL;
    ipc_load_model_t* ipc_model_msg = NULL;
    if (length < sizeof(ipc_load_model_t)) {
        tloge("[convert_sfd_to_sddr] payload length error!\n");
        return ERR_INVALID_MSG_LENGTH;
    }
    ipc_model_msg = (ipc_load_model_t*)payload;
    if (ipc_model_msg->msg_h.tiny_cmd != SUB_CMD_SENSORHUB_LOAD_MODEL) {
        tloge("[convert_sfd_to_sddr] cmd is not load model, no need to convert sfd!");
        return ERR_NONE;
    }
    sfd = ipc_model_msg->model_context.model_blks[0].data_addr;
    tlogd("[convert_sfd_to_sddr] model sfd: %d!\n", sfd);
    sg = sion_get_sglist_from_sfd(sfd, DDR_SEC_TINY);
    if (!sg) {
        tloge("[convert_sfd_to_sddr] get sg failed!\n");
        return ERR_INVALID_POINTER;
    }
    ipc_model_msg->model_context.model_blks[0].data_addr = sg->info[0].phys_addr + VRL_HEAD_LENGTH;
    ipc_model_msg->model_context.model_blks[0].data_size = sg->ion_size - VRL_HEAD_LENGTH;
    tlogi("[convert_sfd_to_sddr] data addr: 0x%x,data_size %d", ipc_model_msg->model_context.model_blks[0].data_addr, ipc_model_msg->model_context.model_blks[0].data_size);
    return ERR_NONE;
}

//receive thread handle
void sensorhub_ipc_wait_for_resp(union ipc_data *msg)
{
    int i;

    tlogd("[sensorhub_ipc_wait_for_resp] \n");
    INT32 ret_lock = pthread_mutex_lock(&g_resp_buf_lock);
    ASSERT_LOCK_RETURN_VOID(ret_lock);

    //get respose data
    for(i = 0; i < MAX_IPC_DATA_LEN; i++)
        sensorhub_ipc_resp[i] = msg->data[i];

    ret_lock = pthread_mutex_unlock(&g_resp_buf_lock);
    ASSERT_LOCK_RETURN_VOID(ret_lock);
    return;
}

//drv init
UINT32 sensorhub_ipc_init()
{
    int ret;

    ret = ipc_recv_notifier_register(AO_S_IPC, AO_MBX6_TO_ACPU, TAG_AI_SVC, sensorhub_ipc_wait_for_resp);
    if(ret) {
        tloge("[sensorhub_ipc_init]ipc recv register failed ret:0x%x\n", ret);
        return ret;
    }

    ret = pthread_mutex_init(&g_resp_buf_lock, NULL);
    if (ret != SRE_OK) {
        tloge("[sensorhub_ipc_init]pthread_mutex_init g_resp_buf_lock failed! ret:0x%x\n", ret);
    }

    memset_s(sensorhub_ipc_resp, sizeof(sensorhub_ipc_resp), 0xFF, sizeof(sensorhub_ipc_resp));

    return ERR_NONE;
}

//send ipc msg to sensorhub
static UINT32 sensorhub_ipc_send_data(void * buf, UINT32 length)
{
    struct ipc_msg sh_send_msg;
    union ipc_data sh_para;
    int ret;

    if (length > MAX_SEND_LEN) {
        tloge("[sensorhub_ipc_send_data]msg length overflow! length:%d\n", length);
        return ERR_INVALID_MSG_LENGTH;
    }

    ret = memcpy_s((void *)(&sh_para), sizeof(sh_para), buf, length);
    if(ret) {
        tloge("[sensorhub_ipc send_data]buf mmcpy err\n");
        return ERR_MBOX_ERR;
    }

    sh_send_msg.src_id = AO_S_ACPU;
    sh_send_msg.dest_id = AO_S_IOMCU;
    sh_send_msg.ipc_id = AO_S_IPC;
    sh_send_msg.mbox_id = AO_MBX1_TO_IOMCU;
    sh_send_msg.msg_len = length >> 2;
    sh_send_msg.ipc_data = &sh_para;

    ret = ipc_async_send(&sh_send_msg);
    if(ret) {
        tloge("[sensorhub_ipc send_data] send failed\n");
        ret = ERR_MBOX_ERR;
    }

    return ret;
}

//ta query for ack
static UINT32 sensorhub_ipc_query_ack(void)
{
    UINT32 mbox_ack = 0x20;
    int ret;
    ret = ipc_mbx_status_query(AO_S_IPC, AO_MBX1_TO_IOMCU);
    if(ret == 0)
    	mbox_ack = REG_IPC_STATUS_ACK;

    return mbox_ack;
}

//ta query for data
static UINT32 sensorhub_ipc_query_data(UINT32 reqid, UINT32 *buf, UINT32 len)
{
    (void)reqid;
    (void)len;
    UINT32 ret = ERR_NONE;
    INT32 ret_lock = pthread_mutex_lock(&g_resp_buf_lock);
    ASSERT_LOCK(ret_lock);
    ret = memcpy_s(buf, sizeof(sensorhub_ipc_resp), sensorhub_ipc_resp, sizeof(sensorhub_ipc_resp));
    ret_lock = pthread_mutex_unlock(&g_resp_buf_lock);
    ASSERT_LOCK(ret_lock);

    return ret;
}

//msg dispatch
static UINT32 sensorhub_ipc_syscall_dispatch(void * buf, UINT32 length)
{
    UINT32 ret = ERR_NONE;
    UINT32 * msg_buf = (UINT32 *)buf;
    UINT32 subcmd;
    void * payload   = (void *)(msg_buf + 1);
    UINT32 subcmd_offset = sizeof(UINT32);
    UINT32 reqid_offset  = sizeof(UINT32);
    UINT32 paylength = length - subcmd_offset;
    if (buf == NULL) {
        return ERR_INVALID_POINTER;
    }

    if (length == 0) {
        return ERR_INVALID_MSG_LENGTH;
    }

    subcmd  = *(msg_buf);
    switch(subcmd) {
    case SENSORHUB_IPC_SEND_DATA:
        tlogd("[sensorhub_ipc_syscall_dispatch] send data to sensorhub!\n");
        tlogd("[sensorhub_ipc_syscall_dispatch] baltomore convert sfd to addr!\n");
        ret = convert_sfd_to_sddr(payload, paylength);
        if (ret != ERR_NONE)
            return ret;
        ret = sensorhub_ipc_send_data(payload, paylength);
        break;
    case SENSORHUB_IPC_QUERY_ACK:
        ret = sensorhub_ipc_query_ack();
        break;
    case SENSORHUB_IPC_QUERY_DATA:
        ret = sensorhub_ipc_query_data(*((UINT32 *)payload), msg_buf +2, paylength - reqid_offset);
        break;
    case SENSORHUB_IPC_DCRYPT:
        ret = dcryptModel(payload, paylength);
        break;
    default:
        tloge("[sensorhub_ipc_syscall_dispatch] invalid subcmd:%d!\n", subcmd);
        return ERR_INVALID_CMD;
    }
    return ret;
}

// sys_call
#include <hmdrv_stub.h> // hack for `HANDLE_SYSCALL`
UINT32 sensorhub_ipc_syscall(UINT32 swi_id, struct drv_param *params, UINT64 permissions)
{
    UINT32 ret = ERR_NONE;
    if (params == NULL || params->args == 0)
        return ERR_INVALID_POINTER;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_NPU_SENSORHUB_IPC, permissions,
                   AI_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        tlogd("[sensorhub_ipc_syscall] syscall receive buf len:%d!\n", args[1]);
        ret = sensorhub_ipc_syscall_dispatch((void *)(uintptr_t)args[0], args[1]);
        args[0] = ret;
        SYSCALL_END

    default:
        return ERR_INVALID_CMD;
    }
    return ERR_NONE;
}
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
//register sys_call, load to specified section beside the other drv
DECLARE_TC_DRV(
    sensorhub_ipc,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    (tc_drv_init_t)sensorhub_ipc_init,
    NULL,
    (tc_drv_syscall_t)sensorhub_ipc_syscall,
    NULL,
    NULL
);
#endif
