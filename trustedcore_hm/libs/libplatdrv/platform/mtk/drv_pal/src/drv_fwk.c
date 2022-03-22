/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk driver framework adapt api
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-08-19
 */
#include "drv_fwk.h"
#include <stdint.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include "api/errno.h"
#include "sys/hm_types.h"
#include "sys/mman.h"
#include "hm_mman_ext.h"
#include "procmgr_ext.h"
#include "mem_drv_map.h"
#include "tee_log.h"
#include "ipc_call.h"
#include "sre_hwi.h"
#include "dlist.h"
#include "tee_time_api.h"
#include "cache_flush.h"
#include "secure_gic_common.h"
#include "vendor_syscall.h"
#include "drv_mem.h"
#include "drv_error.h"

void msee_clean_dcache_range(uintptr_t addr, size_t size)
{
    if ((addr + size < addr) || (addr == 0) || (size == 0)) {
        tloge("clean dcache invalid param\n");
        return;
    }

    __dma_clean_range(addr, (addr + size));
}

void msee_clean_invalidate_dcache_range(uintptr_t addr, size_t size)
{
    if ((addr + size < addr) || (addr == 0) || (size == 0)) {
        tloge("clean invalid dcache invalid param\n");
        return;
    }

    __dma_inv_range(addr, (addr + size));
}

uint32_t msee_mmap_region(uint64_t pa, void **va, size_t size,
    uint32_t flags)
{
    uintptr_t temp_addr = 0;
    cache_mode_type cache_mode;
    secure_mode_type secure_mode = secure;

    if ((va == NULL) || (flags & MSEE_MAP_EXECUTABLE) || ((flags & MSEE_MAP_WRITABLE) == 0)) {
        tloge("mmap region invalid param flags:0x%x\n", flags);
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    if (size > UINT32_MAX) {
        tloge("not support map mem large than UINT32_MAX\n");
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    if (flags & MSEE_MAP_IO)
        cache_mode = cache_mode_device;
    else if (flags & MSEE_MAP_UNCACHED)
        cache_mode = non_cache;
    else
        cache_mode = cache;

    if (flags & MSEE_MAP_ALLOW_NONSECURE)
        secure_mode = non_secure;

    if (sre_mmap(pa, (uint32_t)size, &temp_addr, secure_mode, cache_mode) != 0) {
        tloge("map mem failed\n");
        return DRV_FWK_API_MAP_HARDWARE_FAILED;
    }

    *va = (void *)temp_addr;

    return DRV_FWK_API_OK;
}

uint32_t msee_unmmap_region(const void *va, size_t size)
{
    if (va == NULL || size > UINT32_MAX) {
        tloge("msee unmap region invalid param\n");
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    if (sre_unmap((uintptr_t)va, (uint32_t)size) != 0) {
        tloge("msee unmap region failed\n");
        return DRV_FWK_API_UNMAP_HARDWARE_FAILED;
    }

    return DRV_FWK_API_OK;
}

void *msee_malloc(size_t size)
{
    if (size == 0) {
        tloge("malloc size invalid\n");
        return NULL;
    }

    return malloc(size);
}

void msee_free(void *buf)
{
    if (buf == NULL) {
        tloge("free buf invalid\n");
        return;
    }

    free(buf);
}

void msee_get_system_time(struct msee_time *time)
{
    TEE_Time tee_time = {0};

    if (time == NULL) {
        tloge("invalid time\n");
        return;
    }

    TEE_GetSystemTime(&tee_time);

    time->s = tee_time.seconds;
    time->ms = tee_time.millis;
}

struct irq_pal_data {
    msee_irq_handler_t handler;
    void *data;
};

struct irq_thread_data {
    struct dlist_node node;
    pthread_cond_t irq_cond;
    pthread_mutex_t irq_mutex;
    uint32_t timeout_ms;
    uint32_t irq_num;
    struct irq_pal_data pal_data;
    bool complete_flag;
    bool handler_done;
};

static struct dlist_node g_irq_data_list;
static DLIST_HEAD(g_irq_data_list);
static pthread_mutex_t g_irq_list_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;

static int32_t irq_cond_init(pthread_cond_t *cond)
{
    if (pthread_cond_init(cond, NULL) != 0) {
        tloge("thread cond int failed\n");
        return -1;
    }

    return 0;
}

static int32_t mutex_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

static int32_t add_irq_list_locked(uint32_t irq, struct irq_thread_data *thread_data)
{
    bool irq_existed = false;
    int32_t ret = mutex_lock_ops(&g_irq_list_mutex);
    if (ret != 0) {
        tloge("get irq list mutex failed\n");
        return -1;
    }

    struct irq_thread_data *tmp = NULL;
    dlist_for_each_entry(tmp, &g_irq_data_list, struct irq_thread_data, node) {
        if (tmp->irq_num == irq) {
            tloge("irq:%u existed, cannot add\n", irq);
            irq_existed = true;
            break;
        }
    }

    if (!irq_existed)
        dlist_insert_tail(&thread_data->node, &g_irq_data_list);

    ret = pthread_mutex_unlock(&g_irq_list_mutex);
    if (ret != 0)
        tloge("unlock irq list mutex failed\n");

    if (irq_existed)
        return -1;

    return 0;
}

static void find_irq_node_locked(uint32_t irq, bool delete, struct irq_thread_data **thread_data)
{
    struct irq_thread_data *tmp = NULL;

    int32_t ret = mutex_lock_ops(&g_irq_list_mutex);
    if (ret != 0) {
        tloge("get irq list mutex failed\n");
        return;
    }

    dlist_for_each_entry(tmp, &g_irq_data_list, struct irq_thread_data, node) {
        if (tmp->irq_num == irq) {
            tlogd("find irq:%u\n", irq);
            break;
        }
    }

    if (delete) {
        dlist_delete(&tmp->node);
        free(tmp);
        tmp = NULL;
    } else {
        *thread_data = tmp;
    }

    ret = pthread_mutex_unlock(&g_irq_list_mutex);
    if (ret != 0)
        tloge("unlock irq list mutex failed\n");
}

static void get_irq_pal_data(uint32_t irq, struct irq_pal_data *pal_data)
{
    struct irq_thread_data *tmp = NULL;
    int32_t ret = mutex_lock_ops(&g_irq_list_mutex);
    if (ret != 0) {
        tloge("get irq list mutex failed\n");
        return;
    }

    dlist_for_each_entry(tmp, &g_irq_data_list, struct irq_thread_data, node) {
        if (tmp->irq_num == irq) {
            tloge("find irq:%u\n", irq);
            if (tmp->complete_flag) {
                tloge("find irq:%u has completed\n", irq);
            } else {
                pal_data->handler = tmp->pal_data.handler;
                pal_data->data = tmp->pal_data.data;
            }
            break;
        }
    }

    ret = pthread_mutex_unlock(&g_irq_list_mutex);
    if (ret != 0)
        tloge("unlock irq list mutex failed\n");
}

static void irq_complete_broadcast(uint32_t irq)
{
    struct irq_thread_data *tmp = NULL;
    int32_t ret = mutex_lock_ops(&g_irq_list_mutex);
    if (ret != 0) {
        tloge("get irq list mutex failed\n");
        return;
    }

    dlist_for_each_entry(tmp, &g_irq_data_list, struct irq_thread_data, node) {
        if (tmp->irq_num == irq) {
            tloge("find irq:%u\n", irq);
            if (tmp->complete_flag) {
                tloge("irq:%u has completed cannot broadcast\n", irq);
            } else {
                ret = mutex_lock_ops(&tmp->irq_mutex);
                if (ret != 0) {
                    tloge("get irq:%u lock failed\n", irq);
                    break;
                }
                tmp->handler_done = true;
                pthread_cond_broadcast(&tmp->irq_cond);
                ret = pthread_mutex_unlock(&tmp->irq_mutex);
                if (ret != 0)
                    tloge("get irq:%u unlock failed\n", irq);
            }
            break;
        }
    }

    ret = pthread_mutex_unlock(&g_irq_list_mutex);
    if (ret != 0)
        tloge("unlock irq list mutex failed\n");
}

static void set_irq_complete_flag(uint32_t irq)
{
    struct irq_thread_data *tmp = NULL;
    int32_t ret = mutex_lock_ops(&g_irq_list_mutex);
    if (ret != 0) {
        tloge("get irq list mutex failed\n");
        return;
    }

    dlist_for_each_entry(tmp, &g_irq_data_list, struct irq_thread_data, node) {
        if (tmp->irq_num == irq) {
            tloge("find irq:%u\n", irq);
            tmp->complete_flag =  true;
            break;
        }
    }

    ret = pthread_mutex_unlock(&g_irq_list_mutex);
    if (ret != 0)
        tloge("unlock irq list mutex failed\n");
}

static int32_t irq_thread_data_init(uint32_t irq, msee_irq_handler_t handler, void *data,
    uint32_t timeout_ms, struct irq_thread_data *thread_data)
{
    int32_t ret = robust_mutex_init(&(thread_data->irq_mutex));
    if (ret != 0) {
        tloge("irq:%u mutex init failed\n", irq);
        return -1;
    }

    ret = irq_cond_init(&(thread_data->irq_cond));
    if (ret != 0) {
        tloge("irq:%u cond init failed\n", irq);
        return -1;
    }

    thread_data->pal_data.handler = handler;
    thread_data->pal_data.data = data;
    thread_data->irq_num = irq;
    thread_data->timeout_ms = timeout_ms;
    thread_data->complete_flag = false;
    thread_data->handler_done = false;

    /* keep add to list in the last step */
    ret = add_irq_list_locked(irq, thread_data);
    if (ret != 0) {
        tloge("add irq to list failed\n");
        return -1;
    }

    return 0;
}

static void irq_pal_handler(uint32_t irq)
{
    /*
     * use pal_data store handler info
     * to prevent irq node be deleted
     */
    struct irq_pal_data pal_data = {0};
    int32_t (*msee_handler)(int32_t, void *) = NULL;

    /* complete_flag status shoule be false */
    get_irq_pal_data(irq, &pal_data);

    tlogd("irq handler irq:%u\n", irq);
    msee_handler = pal_data.handler;
    if (msee_handler == NULL) {
        tloge("irq:%u cannot find hanlder\n", irq);
        return;
    }

    int32_t ret = msee_handler(irq, pal_data.data);
    if (ret != 0)
        tloge("msee handler irq:%d ret:0x%x\n", irq, ret);

    irq_complete_broadcast(irq);
}

uint32_t msee_request_irq(uint32_t irq, msee_irq_handler_t handler, size_t flags, uint32_t timeout_ms, void *data)
{
    uint32_t irq_type;

    if ((timeout_ms == 0) || (handler == NULL)) {
        tloge("invalid timeout:%u or handler\n", timeout_ms);
        return MSEE_IRQ_FAIL;
    }

    struct irq_thread_data *thread_data = malloc(sizeof(struct irq_thread_data));
    if (thread_data == NULL) {
        tloge("malloc irq data failed\n");
        return MSEE_IRQ_FAIL;
    }

    if (irq_thread_data_init(irq, handler, data, timeout_ms, thread_data) != 0) {
        /* in this case, irq has not added in list */
        tloge("thread data init failed\n");
        free(thread_data);
        return MSEE_IRQ_FAIL;
    }

    tlogd("request irq:%u\n", irq);
    uint32_t ret = SRE_HwiCreate(irq, 0, INT_SECURE, irq_pal_handler, irq);
    if (ret != SRE_OK) {
        tloge("create irq:%u failed:0x%x\n", irq, ret);
        goto free_irq;
    }

    if ((flags & MSEE_INTR_MODE_MASK_TRIGGER) == MSEE_INTR_MODE_TRIGGER_LEVEL)
        irq_type = IRQ_LEVEL_MODE;
    else
        irq_type = IRQ_EDGE_MODE;

    tlogd("request irq_type:%u\n", irq_type);
    ret = irq_trigger_configure(irq, irq_type);
    if (ret != 0) {
        tloge("irq:%u trigger config failed:0x%x\n", irq, ret);
        goto delete_irq;
    }

    ret = SRE_HwiEnable(irq);
    if (ret != SRE_OK) {
        tloge("enable irq:%u failed:0x%x\n", irq, ret);
        goto delete_irq;
    }

    return 0;

delete_irq:
    ret = SRE_HwiDelete(irq);
    if (ret != 0)
        tloge("delete irq:%u failed:0x%x\n", irq, ret);

free_irq:
    find_irq_node_locked(irq, true, NULL); /* find and delete it */

    return MSEE_IRQ_FAIL;
}

uint32_t msee_wait_for_irq_complete(uint32_t irq)
{
    struct irq_thread_data *thread_data = NULL;

    find_irq_node_locked(irq, false, &thread_data);
    if (thread_data == NULL) {
        tloge("find irq:%u thread data failed\n", irq);
        return MSEE_IRQ_FAIL;
    }

    pthread_mutex_t *mtx = &thread_data->irq_mutex;
    pthread_cond_t *cond = &thread_data->irq_cond;
    uint32_t timeout_ms = thread_data->timeout_ms;
    struct timespec timeout = {0};

    int32_t ret = get_lock_time(timeout_ms, &timeout);
    if (ret != 0) {
        tloge("get lock time failed\n");
        return MSEE_IRQ_FAIL;
    }

    ret = mutex_lock_ops(mtx);
    if (ret != 0) {
        tloge("lock irq:%u mutex failed\n", irq);
        return MSEE_IRQ_FAIL;
    }

    tlogd("wait for irq before cond wait\n");
    while (!thread_data->handler_done) {
        ret = pthread_cond_timedwait(cond, mtx, &timeout);
        if (ret == ETIMEDOUT) {
            tloge("cond wait irq:%u timeout:(%u)ms\n", irq, timeout_ms);
            pthread_mutex_unlock(mtx);
            set_irq_complete_flag(irq);
            return MSEE_IRQ_TIMEOUT;
        }

        if (ret != 0) {
            tloge("cond wait irq:%u failed\n", irq);
            pthread_mutex_unlock(mtx);
            return MSEE_IRQ_FAIL;
        }
    }

    tlogd("wait for irq after cond wait end\n");
    if (pthread_mutex_unlock(mtx) != 0)
        tloge("mutex irq:%u lock failed\n", irq);

    set_irq_complete_flag(irq);

    return 0;
}

void msee_free_irq(uint32_t irq)
{
    struct irq_thread_data *thread_data = NULL;
    find_irq_node_locked(irq, false, &thread_data);
    if (thread_data == NULL) {
        tloge("cannot find irq:%u data\n", irq);
        return;
    }

    if (!thread_data->complete_flag) {
        tloge("irq:%u has not completed\n", irq);
        return;
    }

    uint32_t ret = SRE_HwiDisable(irq);
    if (ret != 0) {
        tloge("disable irq:%u failed:0x%x\n", irq, ret);
        return;
    }

    ret = SRE_HwiDelete(irq);
    if (ret != 0)
        tloge("delete irq:%u failed:0x%x\n", irq, ret);

    tlogd("free irq end\n");
    find_irq_node_locked(irq, true, NULL); /* find and delete */
}

/*
 * parameters(to/from/size/job_handler) will check in drv_map_from_task_under_tbac_handle
 * if flags has MSEE_MAP_ALLOW_NONSECURE, cannot handle
 */
uint32_t msee_map_user(void **to, const void *from, size_t size, uint32_t flags)
{
    uint64_t temp_addr;
    int32_t prot;
    pid_t caller_pid;
    uint64_t job_handler;

    int32_t err = get_callerpid_and_job_handler(&caller_pid, &job_handler);
    if (err != 0) {
        tloge("get pid and job handler failed\n");
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    pid_t self_pid = hm_getpid();
    if (self_pid == HM_ERROR) {
        tloge("pid falied, caller_pid:0x%x self_pid:0x%x\n", caller_pid, self_pid);
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    if (((flags & MSEE_MAP_EXECUTABLE) != 0) || ((flags & MSEE_MAP_IO) != 0)) {
        tloge("drv map invalid flag:0x%x\n", flags);
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    err = drv_map_from_task_under_tbac_handle((uint32_t)caller_pid, (uintptr_t)from, size,
        (uint32_t)self_pid, &temp_addr, &prot, job_handler);
    if (err != 0) {
        tloge("drv map from task failed\n");
        return DRV_FWK_API_MAP_TASK_BUFFER_FAILED;
    }

    if ((flags & MSEE_MAP_WRITABLE) && ((prot & PROT_WRITE) == 0)) {
        tloge("drv map write flag:0x%x invalid\n", flags);
        if (hm_munmap((const void *)(uintptr_t)temp_addr, size) != 0)
            tloge("unmap temp addr failed\n");
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    *to = (void *)(uintptr_t)temp_addr;
    return DRV_FWK_API_OK;
}

uint32_t msee_unmap_user(const void *to, uint32_t size)
{
    if ((to == NULL) || (size == 0)) {
        tloge("msee unmap user invalid param\n");
        return DRV_FWK_API_INVALIDATE_PARAMETERS;
    }

    if (hm_munmap(to, size) != 0) {
        tloge("msee unmap user failed\n");
        return DRV_FWK_API_UNMAP_HARDWARE_FAILED;
    }

    return DRV_FWK_API_OK;
}

int32_t msee_smc_call(uint32_t smc_nr, uint32_t args0, uint32_t args1,
    uint32_t args2, uint32_t *smc_ret)
{
    kcall_tee_smc_atf_t param;

    param.x1 = args0;
    param.x2 = args1;
    param.x3 = args2;
    param.x4 = 0;

    int32_t ret = switch_to_atf_ret(smc_nr, &param);
    if (ret != 0) {
        tloge("smc to atf failed, ret=0x%x\n", ret);
        return DRV_FWK_API_SMC_CALL_FAILED;
    }

    if (smc_ret != NULL)
        *smc_ret = (uint32_t)param.x4;

    return DRV_FWK_API_OK;
}
