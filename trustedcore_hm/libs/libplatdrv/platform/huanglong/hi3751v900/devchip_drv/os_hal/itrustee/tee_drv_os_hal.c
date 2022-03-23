/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee drv hal api for itrustee
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "stdio.h"
#include "module_mgr.h"
#include "tee_drv_os_hal.h"
#include "tee_time_api.h"
#include "stdarg.h"
#include "sre_sys.h"
#include "sre_hwi.h"
#include "sre_msg.h"
#include "mem_ops.h"
#include "drv_mem.h"
#include "drv_module.h"
#include "legacy_mem_ext.h"
#include "register_ops.h"
#include "timer.h"
#include "sys_timer.h"
#include "drv_legacy_def.h"
#include "drv_param_type.h"
#include "mm_kcall.h"

void __do_panic(const char *file __MAYBE_UNUSED, const int line __MAYBE_UNUSED,
                const char *func __MAYBE_UNUSED, const char *msg __MAYBE_UNUSED)
{
    if (file == NULL && func == NULL && msg == NULL) {
        os_hal_error("Panic\n");
    } else {
        os_hal_error("Panic %s%s%sat %s:%d %s%s%s\n",
                     msg ? "'" : "", msg ? msg : "", msg ? "' " : "",
                     file ? file : "?", file ? line : 0,
                     func ? "<" : "", func ? func : "", func ? ">" : "");
    }
    hm_dump_current_stack();
    while (1) { }
}

#define MAX_PRINT_SIZE 256
static char g_buf[MAX_PRINT_SIZE];

int hi_tee_drv_hal_printf(const char *fmt, ...)
{
    int retval = 0;
/* uart should not output in release version, modified by hisilicon */
#ifdef CFG_HI_TEE_LOG_SUPPORT
    va_list ap;
    char *str = NULL;

    va_start(ap, fmt);
    retval = vsnprintf_s(g_buf, MAX_PRINT_SIZE, MAX_PRINT_SIZE - 1, fmt, ap);
    va_end(ap);

    if (retval < 0) {
        /* Format error */
        return 0;
    }
    if (retval >= (int)sizeof(g_buf)) {
        /* Output was truncated */
        return 0;
    }

    str = g_buf;
    while (*str) {
        putchar (*str++);
    }
#endif
    return retval;
}

void *hi_tee_drv_hal_phys_to_virt(unsigned long long pa)
{
    if (pa <= SYS_IO_ADDR_END && pa >= SYS_IO_ADDR_START) {
        return (void *)(uintptr_t)pa;
    } else if (pa <= 0x10000000) {
        return (void *)(uintptr_t)(pa + 0xB0000000);
	} else {
        os_hal_error("Phys to virt failed, pa:%llx\n", pa);
        return NULL;
    }
}

/* when the phys_addr over 0xFFFFFFFF, this func need debug */
unsigned long long hi_tee_drv_hal_virt_to_phys(const void *va)
{
    unsigned long long pa = 0;
    int ret;

    ret = virt_to_phys((unsigned long long)(uintptr_t)va, &pa);
    if (ret) {
        os_hal_error("virt_to_phys failed, va:%p\n", va);
        return 0;
    }

    return pa;
}

void *hi_tee_drv_hal_asm_memmove(void *dest, const void *src, unsigned int n)
{
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }

    return asm_memmove(dest, src, n);
}

void *hi_tee_drv_hal_asm_memcpy(void *dest, const void *src, unsigned int n)
{
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }

    return asm_memcpy(dest, src, n);
}

unsigned long long hi_tee_drv_hal_get_system_time_in_us(void)
{
    unsigned long long stamp;
    unsigned long long us;
    unsigned long long seconds;
    unsigned long long millis;

    TEE_Time cur_time;

    stamp = SRE_ReadTimestamp();
    cur_time.seconds = stamp >> 32; /* high 32bit save the second data */
    cur_time.millis = stamp & 0xffffffff;
    seconds = cur_time.seconds;
    millis  = cur_time.millis;
    us = (unsigned long long)(seconds * 1000000 + millis / 1000); /* 1s: 1000000us, 1us: 1000ns */
    return us;
}

void hi_tee_drv_hal_udelay(unsigned long us)
{
    /* NOTE: Should not use SRE_DelayUs(us), it will delay in ms. */
    unsigned int cycles;
    unsigned int counts;
    unsigned int cur;
    unsigned int end;

    if (us > (1000 * 1000)) { /* 1s is 1000 * 1000us */
        os_hal_error("Delay failed, the value %d should be less than 1000000\n", us);
        return;
    }

    /*
     * the return of __SRE_ReadTimestamp is a 64bit data,
     * the high 32bit is second and the low 32bit is nanosecond.
     */
    cycles = us * 1000; /* 1us is 1000ns */
    counts = 0;
    end = (unsigned int)__SRE_ReadTimestamp();
    while (counts < cycles) {
        cur = (unsigned int)__SRE_ReadTimestamp();
        if (cur >= end) {
            counts += cur - end;
        } else {
            counts += 1000000000 - end + cur; /* 1s is 1000000000ns */
        }
        end = cur;
    }
}

void hi_tee_drv_hal_mdelay(unsigned long msec)
{
    SRE_DelayMs(msec);
}

void hi_tee_drv_hal_msleep(unsigned long msec)
{
    if (SRE_SwMsleep(msec)) {
        os_hal_error("Sleep failed\n");
    }
}

int hi_tee_drv_hal_mutex_init(const char *name, struct hi_tee_hal_mutex *mutex)
{
    (void)name;

    if (mutex == NULL) {
        return -1;
    }

    return pthread_mutex_init(&(mutex->mutex), NULL);
}

int hi_tee_drv_hal_mutex_destroy(struct hi_tee_hal_mutex *mutex)
{
    int ret;

    if (mutex == NULL) {
        os_hal_error("Mutex destroy failed, mutex is null\n");
        return -1;
    }

    ret = pthread_mutex_destroy(&(mutex->mutex));
    if (ret) {
        os_hal_error("Mutex destory faield.\n");
        return -1;
    }

    return 0;
}

int hi_tee_drv_hal_mutex_lock(struct hi_tee_hal_mutex *mutex)
{
    int ret;

    if (mutex == NULL) {
        os_hal_error(" Mutex lock failed, mutex is null\n");
        return -1;
    }

    ret = pthread_mutex_lock(&(mutex->mutex));
    if (ret) {
        os_hal_error(" Mutex lock failed.");
        return -1;
    }

    return 0;
}

int hi_tee_drv_hal_mutex_unlock(struct hi_tee_hal_mutex *mutex)
{
    int ret;

    if (mutex == NULL) {
        os_hal_error("mutex is null\n");
        return -1;
    }
    ret = pthread_mutex_unlock(&(mutex->mutex));
    if (ret) {
        os_hal_error("mutex unlock failed, ret:%d .\n", ret);
        return -1;
    }
    return 0;
}

void hi_tee_drv_hal_spin_lock_init(struct hi_tee_hal_spinlock *lock)
{
    (void)lock;
}

void hi_tee_drv_hal_spin_lock(struct hi_tee_hal_spinlock *lock)
{
    (void)lock;
}

void hi_tee_drv_hal_spin_unlock(struct hi_tee_hal_spinlock *lock)
{
    (void)lock;
}

unsigned int hi_tee_drv_hal_spin_lock_irqsave(struct hi_tee_hal_spinlock *lock)
{
    (void)lock;
    irq_lock();
    return 0;
}

void hi_tee_drv_hal_spin_unlock_irqrestore(struct hi_tee_hal_spinlock *lock, unsigned int status)
{
    (void)lock;
    (void)status;
    irq_unlock();
}

void *hi_tee_drv_hal_malloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    return SRE_MemAlloc(OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, size);
}

void hi_tee_drv_hal_free(void *ptr)
{
    if (ptr == NULL) {
        os_hal_error("Memery free failed, addr is NULL\n");
        return;
    }

    if (SRE_MemFree(OS_MID_SYS, ptr)) {
        os_hal_error("Memery free failed \n");
    }
}

void *hi_tee_drv_hal_remap(unsigned long long pa, size_t size, bool is_secure, bool cached)
{
    unsigned int virt_addr = 0;
    secure_mode_type sec_mode = is_secure ? secure : non_secure;

    return sre_mmap(pa, size, &virt_addr, sec_mode, cached) ? NULL : (void *)(uintptr_t)virt_addr;
}

void hi_tee_drv_hal_unmap(void *va, size_t size)
{
    if (va == NULL || size == 0) {
        os_hal_error("Non secure memery unmap failed, va:0x%p, size:0x%x\n", va, size);
        return;
    }

    if (sre_unmap((unsigned int)(uintptr_t)va, size)) {
        os_hal_error("Non secure memery unmap failed, va:0x%p, size:0x%x\n", va, size);
    }
}

int hi_tee_drv_hal_current_uuid(TEE_UUID *uuid)
{
    int ret;
    spawn_uuid_t ta_uuid = {0};
    unsigned int ta_pid;

    if (uuid == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = SRE_TaskSelf(&ta_pid);
    if (ret != 0) {
        os_hal_error("get ta pid failed!\n");
        return -1;
    }

    ret = hm_getuuid(ta_pid & 0xFFFF, &ta_uuid);
    if (ret) {
        os_hal_error("get uuid failed!\n");
        return ret;
    }

    ret = memcpy_s(uuid, sizeof(TEE_UUID), &ta_uuid.uuid, sizeof(ta_uuid.uuid));
    if (ret != EOK) {
        os_hal_error("memcpy failed!\n");
        return -1;
    }

    return 0;
}

int hi_tee_drv_hal_request_irq(unsigned int irq, void *handler, unsigned int flag, const void *dev)
{
    int ret;

    (void)flag;
    ret = SRE_HwiCreate(irq, 0xa0, 0, (HWI_PROC_FUNC)handler, (unsigned)(uintptr_t)dev);
    if (ret) {
        os_hal_error("Create interrupt failed, irq:0x%x, ret:0x%x\n", irq, ret);
        return ret;
    }

    ret = SRE_HwiEnable(irq);
    if (ret) {
        os_hal_error("Eenable interrupt failed, irq:0x%x, ret:0x%x\n", irq, ret);
        if (SRE_HwiDelete(irq) != TEE_SUCCESS) {
            os_hal_error("Delete interrupt failed, irq:0x%x\n", irq);
        }
        return ret;
    }
    return TEE_SUCCESS;
}

void hi_tee_drv_hal_unregister_irq(unsigned int irq)
{
    int ret;

    ret = SRE_HwiDisable(irq);
    if (ret) {
        os_hal_error("Disable interrupt failed, irq:0x%x, ret:0x%x\n", irq, ret);
        return;
    }

    ret = SRE_HwiDelete(irq);
    if (ret) {
        os_hal_error("Delete interrupt failed, irq:0x%x, ret:0x%x\n", irq, ret);
        return;
    }
}

void hi_tee_drv_hal_raise_pi(unsigned int irq)
{
    int ret = SRE_HwiNotify(irq);
    if (ret) {
        os_hal_error("Notify interrupt failed, irq:0x%x, ret:0x%x\n", irq, ret);
        return;
    }
}

void hi_tee_drv_hal_backtraces(void)
{
    hm_dump_current_stack();
}

void hi_tee_drv_hal_sys_reset(void)
{
    while (1) { /* for security */
        /* unclock wdg   */
        writel(0x1ACCE551, (volatile unsigned *)(uintptr_t)(REG_BASE_SYSRES + 0xc00));
        /* wdg load value  */
        writel(0x100, (volatile unsigned *)(uintptr_t)REG_BASE_SYSRES);
        /*  bit0: int enable bit1: reboot enable  */
        writel(0x003, (volatile unsigned *)(uintptr_t)(REG_BASE_SYSRES + 0x0008));
    }
}

void hi_tee_drv_hal_get_rodata_pa_range(unsigned long long *base, unsigned long long *size)
{
    unsigned long long start = 0;
    unsigned long long len = 0;

    if (base == NULL || size == NULL) {
        os_hal_error("err args.\n");
        return;
    }

    teecall_cap_get_img_text_paddr(&start, &len);
    if (len == 0) {
        os_hal_error("get text addr failed\n");
        *base = 0;
        *size = 0;
        return;
    }

    *base = start & 0xFFFFFFFFFFFF0000;
    *size = len + start - *base;
}

static int tee_hal_gen_rand(unsigned int *num)
{
    unsigned int i = 0;
    unsigned int rng_value = 0x4B693C87;  /* 0x4B693C87, a random data */
    unsigned int rng_stat;

    if (num == NULL) {
        os_hal_error("err args\n");
        return -1;
    }
#ifndef CFG_HI_TEE_FPGA_SUPPORT
    irq_lock();
    write32((uintptr_t)OS_HAL_RNG_DATA_CTRL, 0x8);
    for (i = 0; i < 0x10000; i++) {  /* about 10ms */
        asm("nop");
        asm("nop");
        rng_stat = read32((uintptr_t)OS_HAL_RNG_DATA_CNT);
        if (((rng_stat >> 8) & 0x3F) > 0) { /* 8, 0x3F ?bit[13:8] */
            rng_value = read32((uintptr_t)OS_HAL_RNG_DATA_VAL);
            break;
        }
    }
    irq_unlock();

    if (i >= 0x10000) {
        os_hal_error("get rng time out.\n");
        return -1;
    }

    if (rng_value == 0 || rng_value == 0xffffffff || rng_value == 0x4B693C87) {  /* 0x4B693C87, rng_value init data */
        os_hal_error("get rng failed.\n");
        return -1;
    }
#endif
    *num = rng_value;
    return 0;
}

int hi_tee_drv_hal_rng_generate(void *buffer, size_t len)
{
    char *buf = buffer;
    unsigned int i;
    unsigned int byte;
    unsigned int rand_num = 0xA5A55A5A;
    unsigned int rand_len = sizeof(rand_num);
    int ret = 0;

    if (buf == NULL) {
        return -1;
    }

    for (i = 0; i < len; i += byte) {
        if (tee_hal_gen_rand(&rand_num) != 0) {
            return -1;
        }

        byte = len - i;
        byte = (byte > rand_len) ? rand_len : byte;
        ret = memcpy_s(buf + i, len - i, &rand_num, byte);
        if (ret) {
            return -1;
        }
    }

    return 0;
}

/*
 * Note: the cache operation function don't consider outer L2
 * Currently, Hisilicon Socs don't use outer L2 cache
 */
void hi_tee_drv_hal_dcache_flush(void *va, size_t len)
{
    if (va == NULL || len == 0) {
        return;
    }

    __dma_flush_range(va, va + len - 1);
}

void hi_tee_drv_hal_dcache_flush_all(void)
{
}

void hi_tee_drv_hal_dcache_invalidate(void *va, size_t len)
{
    (void)va;
    (void)len;
    os_hal_error("Trustedcore not support\n");
}

int hi_tee_drv_hal_timer_init(hi_tee_hal_timer *tm_event)
{
    if (tm_event == NULL) {
        return TEE_ERROR_GENERIC;
    }

    tm_event->timer = (void *)SRE_TimerEventCreate((sw_timer_event_handler)tm_event->handler,
                                                   TIMER_CLASSIC, (void *)&tm_event->data);
    if (tm_event->timer == NULL) {
        os_hal_error("Create timer event failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

int hi_tee_drv_hal_timer_start(hi_tee_hal_timer *tm_event)
{
    timeval_t timer_val;
    int ret;

    if (tm_event == NULL) {
        return -1;
    }

    timer_val.tval.nsec = (tm_event->expires - (tm_event->expires / 1000000) * 1000000) * 1000; /* 1s 1000000us */
    timer_val.tval.sec  = tm_event->expires / 1000000; /* 1s 1000000us */
    ret = SRE_TimerEventStart((timer_event *)tm_event->timer, &timer_val);
    if (ret) {
        os_hal_error("Start timer failed, ret:0x%x\n", ret);
        (void)SRE_TimerEventDestroy((timer_event *)tm_event->timer);
        return ret;
    }
    return ret;
}

int hi_tee_drv_hal_timer_delete(hi_tee_hal_timer *tm_event)
{
    if (tm_event == NULL) {
        return -1;
    }

    SRE_TimerEventStop((timer_event *)tm_event->timer);
    return SRE_TimerEventDestroy((timer_event *)tm_event->timer);
}

bool hi_tee_drv_hal_access_check(const void *addr, size_t size)
{
    if (addr == NULL || size == 0) {
        return false;
    }

    return !tee_mmu_check_access_rights(ACCESS_READ | ACCESS_WRITE, (unsigned int)(uintptr_t)addr, size);
}

bool hi_tee_drv_hal_read_right_check(const void *addr, size_t size)
{
    if (addr == NULL || size == 0) {
        return false;
    }

    return !tee_mmu_check_access_rights(ACCESS_READ, (unsigned int)(uintptr_t)addr, size);
}

bool hi_tee_drv_hal_write_right_check(const void *addr, size_t size)
{
    if (addr == NULL || size == 0) {
        return false;
    }

    return !tee_mmu_check_access_rights(ACCESS_WRITE, (unsigned int)(uintptr_t)addr, size);
}

static unsigned int g_smmu_agent_sendmsg_pid = 0;

void hi_tee_drv_set_smmu_agent_msg_info(unsigned int msg_pid)
{
    g_smmu_agent_sendmsg_pid = msg_pid;
}

int hi_tee_drv_hal_agentcall(unsigned int agent_id, unsigned int send_msgid, void *buffer, size_t len)
{
    int ret = -1;

    if (g_smmu_agent_sendmsg_pid && len <= MAX_AGENT_CONTENT_LENGHT) {
        unsigned int msgid = 0;
        struct hi_tee_hal_agent_msg agentmsg = {0};

        agentmsg.agent_id = agent_id;
        agentmsg.agent_pid  = get_selfpid();
        if (memcpy_s(agentmsg.agent_content, MAX_AGENT_CONTENT_LENGHT, buffer, len) != EOK) {
            return -1;
        }
        __SRE_MsgSnd(send_msgid, g_smmu_agent_sendmsg_pid, (void *)&agentmsg, sizeof(agentmsg));
        ret = __SRE_MsgRcv(OS_WAIT_FOREVER, (void *)&msgid, (void *)&agentmsg, sizeof(agentmsg));
        if (send_msgid == msgid) {
            if (memcpy_s(buffer, len, agentmsg.agent_content, len) != EOK) {
                return -1;
            }
        } else {
            ret = -1;
        }
    }
    return ret;
}

int hi_tee_drv_hal_map_sg(struct hi_tee_hal_sg_info *sg, bool is_secure, bool cached, bool user_map, void *va)
{
    struct hi_tee_hal_sg_info sginfo;
    /* NOTE: value 1 means non_secure in trustedcore */
    secure_mode_type sec_mode = is_secure ? secure : non_secure;
    int ret;

    if (sg == NULL || va == NULL) {
        os_hal_error("error args\n");
        return -1;
    }

    ret = memset_s(&sginfo, sizeof(struct hi_tee_hal_sg_info), 0, sizeof(struct hi_tee_hal_sg_info));
    if (ret != EOK) {
        os_hal_error("memset_s failed\n");
        return -1;
    }
    ret = memcpy_s(&sginfo, sizeof(struct hi_tee_hal_sg_info), sg, sizeof(struct hi_tee_hal_sg_info));
    if (ret != EOK) {
        os_hal_error("memcpy_s failed\n");
        return -1;
    }

    if (sginfo.pageinfoaddr == NULL || sginfo.size == 0) {
        os_hal_error("sginfo error, pageinfoaddr = 0x%X, size = 0x%X\n", sginfo.pageinfoaddr, sginfo.size);
        return -1;
    }

    return sre_mmap_scatter((TEE_PAGEINFO *)sginfo.pageinfoaddr, sginfo.nblocks, va, sginfo.size,
                            sec_mode, cached, user_map ? USED_BY_USR : USED_BY_SVC);
}

int hi_tee_drv_hal_unmap_sg(const void *va, size_t size, bool is_secure, bool user_map)
{
    (void)is_secure;

    if (va == NULL || size == 0) {
        return -1;
    }

    return sre_munmap_scatter((unsigned int)(uintptr_t)va, size, user_map ? USED_BY_USR : USED_BY_SVC);
}

int hi_tee_drv_hal_permission_check(unsigned long long crt_permissions, unsigned long long check_permissions)
{
    return (check_permissions & crt_permissions) == check_permissions ? 0 : -1;
}

int hi_tee_drv_hal_user_mmap(void **addr, unsigned int size)
{
    void *self_vaddr = NULL;
    unsigned int ta_vaddr;
    unsigned int ta_pid;
    int self_pid;
    int prot;
    int ret;

    if (addr == NULL || *addr == NULL || size == 0) {
        os_hal_error("invalid params! addr is NULL\n");
        return -1;
    }

    ta_vaddr = *((unsigned int *)addr);

    self_pid = hm_getpid();
    if (self_pid < 0) {
        os_hal_error("get self pid failed!\n");
        return -1;
    }

    ret = SRE_TaskSelf(&ta_pid);
    if (ret != 0) {
        os_hal_error("get ta pid failed!\n");
        return -1;
    }

    ret = drv_map_from_task(ta_pid, ta_vaddr, size, (unsigned int)self_pid, (unsigned int *)&self_vaddr, &prot);
    if (ret != 0) {
        os_hal_error("syscall_access_check(0x%x, 0x%x) failed: %d.", ta_vaddr, size, ret);
        return -1;
    }

    if (self_vaddr == NULL) {
        os_hal_error("malloc size 0x%x failed.", size);
        return -1;
    }

    if (size > 0x100000) {
        os_hal_error("buffer size too long, size is %x n", size);
    }

    *addr = self_vaddr;
    return 0;
}

int hi_tee_drv_hal_user_munmap(void *addr, unsigned int size)
{
    int self_pid;

    if (addr == 0 || size == 0) {
        os_hal_error("invalid params! addr is NULL\n");
        return -1;
    }

    self_pid = hm_getpid();
    if (self_pid < 0) {
        os_hal_error("get self pid failed!\n");
        return -1;
    }

    __task_unmap_from_ns_page((unsigned int)self_pid, (unsigned int)(uintptr_t)addr, size);
    return 0;
}

int hi_tee_drv_hal_module_register(const unsigned int module_id, hi_tee_hal_syscall fn)
{
    return tee_drv_module_register(module_id, fn);
}

int hi_tee_drv_hal_ioctl(int swi_id, struct drv_param *params, unsigned long long permissions)
{
    unsigned int ret;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_HISILICON_IOCTL, permissions, GENERAL_GROUP_PERMISSION)
            if (args[2] != 0) {
                /*
                 * here do the basic access check for in the syscall entry
                 * but more accurate check should be done the driver itself
                 */
                if (args[3] == 0) {
                    ACCESS_CHECK(args[2], 4) /* sizeof(unsigned int) is 4 */
                } else {
                    ACCESS_CHECK(args[2], args[3])
                }
			}
            ret = tee_hisilicon_ioctl(args[0], args[1], (void *)(uintptr_t)args[2], args[3]);
            args[0] = ret;
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

hi_tee_drv_hal_driver_init_late(drv_hal, 0, NULL, hi_tee_drv_hal_ioctl, NULL, NULL);

