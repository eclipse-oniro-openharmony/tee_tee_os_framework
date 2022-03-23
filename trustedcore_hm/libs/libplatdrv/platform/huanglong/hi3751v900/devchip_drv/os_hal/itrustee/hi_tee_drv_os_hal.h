/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: the hal api for itrustee
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __HI_TEE_DRV_OS_HAL_H
#define __HI_TEE_DRV_OS_HAL_H

#include "drv_pal.h" /* task_caller */
#include "sre_access_control.h"
#include "hmdrv_stub.h"
#include "errno.h"
#include "sre_task.h"
#include "drv_module.h"
#include "pthread.h"
#include "securec.h"
#include "plat_cfg.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"
#include "ta_framework.h"

/* compiler __attribute__ macros for code easier to read */
#define __DEPRECATED      __attribute__((deprecated))
#define __WEAK            __attribute__((weak))
#define __NORETURN        __attribute__((noreturn))
#define __UNUSED          __attribute__((unused))
#define __MAYBE_UNUSED    __attribute__((unused))

/* The irq handler return value */
#define HI_TEE_HAL_IRQ_HANDLED 1
#define HI_TEE_HAL_IRQ_NONE    0

typedef unsigned(*hi_tee_hal_timer_handler)(unsigned long);
typedef int(*hi_tee_hal_syscall)(const unsigned int, void *, const size_t);

struct hi_tee_hal_mutex {
    pthread_mutex_t mutex;
};

struct hi_tee_hal_spinlock {
    unsigned spin_lock;
};

#define MAX_AGENT_CONTENT_LENGHT  128
struct hi_tee_hal_agent_msg {
    unsigned int agent_id;
    unsigned int agent_pid;
    char agent_content[MAX_AGENT_CONTENT_LENGHT];
};

struct hi_tee_hal_sg_info {
    void *pageinfoaddr;    /* The physic address of the sglist structure */
    unsigned int nblocks;  /* The number of frags in the sglist */
    size_t size;           /* The memory size of the whole sglist */
};

/**
 * struct tee_hal_timer_t - describe a kernel space timer
 *
 * handler   The timer callback function handler
 * expires   The expire time of the timer, the resolution is micro seconds
 *           for example, the expires is set to 10, it means the timer will
 *           be called after 10us
 * data      The global timer data which will be pass to the timer callback
 *           handler, usually, it's set to the pointer to the timer itself
 * timer     The internal pointer which really implements the timer
 *
 */
typedef struct {
    hi_tee_hal_timer_handler  handler;
    unsigned long long        expires;
    unsigned long             data;  /* Private data */
    void                     *timer; /* internel data */
} hi_tee_hal_timer;

void __do_panic(const char *file, const int line, const char *func, const char *msg);

#if defined(CFG_HI_TEE_DEBUG_SUPPORT)
#define __panic(str)    __do_panic(__FILE__, __LINE__, __func__, str)
#else
#define __panic(str)    __do_panic((void *)0, 0, (void *)0, (void *)0)
#endif

#define _panic0()   __panic((void *)0)
#define _panic1(s)  __panic(s)
#define _panic_fn(a, b, name, ...) name

/*
 * The active panic function for crital errors which can't be processed.
 * This function will verbose the callstack(depends on the specified CFG) and fall
 * into a dead loop.
 */
#define hi_tee_drv_hal_panic(...) _panic_fn("", ##__VA_ARGS__, _panic1, _panic0)(__VA_ARGS__)

/*
 * Module init helper micros which is similar as Linux module_init
 * they are used to register module init entrypoint to the kernel.
 *
 * The calling sequence is as follow:
 * 1.   hi_tee_drv_hal_service_init
 * 2.   hi_tee_drv_hal_service_init_late
 * 3.   hi_tee_drv_hal_driver_init
 * 4.   hi_tee_drv_hal_driver_init_late
 */
#define hi_tee_drv_hal_service_init(name, multi, setup, syscall, suspend, resume)      \
    DECLARE_TC_DRV(name, 0, 0, 0, TC_DRV_EARLY_INIT, setup, NULL, syscall, suspend, resume)
#define hi_tee_drv_hal_service_init_late(name, multi, setup, syscall, suspend, resume) \
    DECLARE_TC_DRV(name, 0, 0, 0, TC_DRV_ARCH_INIT, setup, NULL, syscall, suspend, resume)
#define hi_tee_drv_hal_driver_init(name, multi, setup, syscall, suspend, resume)       \
    DECLARE_TC_DRV(name, 0, 0, 0, TC_DRV_MODULE_INIT, setup, NULL, syscall, suspend, resume)
#define hi_tee_drv_hal_driver_init_late(name, multi, setup, syscall, suspend, resume)  \
    DECLARE_TC_DRV(name, 0, 0, 0, TC_DRV_LATE_INIT, setup, NULL, syscall, suspend, resume)

/*
 * hi_tee_drv_hal_printf - Standard printf functions in kernel
 */
int hi_tee_drv_hal_printf(const char *fmt, ...);

/*
 * hi_tee_drv_hal_phys_to_virt() - convert physic address to virtual address
 * Often the module driver only has got the physic address, but can only
 * access the virt address.
 * phys_to_virt will convent the physic address to virtual address which
 * can be accessed by cpu, Note: this physic address will be mapped already.
 * In trustedcore, only support IO address.
 *
 * @param pa                The physic address which is to be converted.
 *
 * @return NULL             The physic to virt convert failed.
 * @return virtual address  The virtual address.
 */
void *hi_tee_drv_hal_phys_to_virt(unsigned long long pa);

/*
 * hi_tee_drv_hal_virt_to_phys() - convert virtual address to physic address
 * The hardware can only accept physic address, but the software owns the virtual
 * address only.So virt to phys convert is needed.
 *
 * @param va                The virtual address which is to be converted.
 *
 * @return NULL             The virtual to physic convert failed.
 * @return physic address   The physic address.
 */
unsigned long long hi_tee_drv_hal_virt_to_phys(const void *va);

/*
 * hi_tee_drv_hal_asm_memmove() - mem move by asm
 *
 * @param dest  The dest address that move to.
 * @param src   The src address that move from.
 * @param n     the size of data to move.
 *
 * @return NULL  mem move failed.
 * @return addr  dest addr.
 */
void *hi_tee_drv_hal_asm_memmove(void *dest, const void *src, unsigned int n);

/*
 * hi_tee_drv_hal_asm_memcpy() - mem copy by asm
 *
 * @param dest  The dest address that copy to.
 * @param src   The src address that copy from.
 * @param n     the size of data to copy.
 *
 * @return NULL  mem copy failed.
 * @return addr  dest addr.
 */
void *hi_tee_drv_hal_asm_memcpy(void *dest, const void *src, unsigned int n);

/*
 * These functions are all time relative functions
 *
 * 1. get_time_in_ms/us will return the system time in ms/us which is the
 * tee time and depends on the arm cp15 timer.
 *
 * 2. udelay/mdelay are used for short dead loop, and there two functions
 * also depends on the arm cp15 timer.
 *
 * 3. msleep is used for a relative long delay, and this function will release
 * the cpu and return back to the REE world, maybe is not so accurate which maybe
 * delayed by REE world but this function more effective.
 */
/*
 * hi_tee_drv_hal_get_system_time_in_us() - get the system monotonic time.
 * this function is base on the system secure timer.
 *
 * @return the system monotonic time in us.
 */
unsigned long long hi_tee_drv_hal_get_system_time_in_us(void);

/*
 * hi_tee_drv_hal_udelay() - delay helper function in resolution us.
 * this function is base on the system secure timer, used for short dead loop
 *
 * @param us   The time to delay.
 */
void hi_tee_drv_hal_udelay(unsigned long us);

/*
 * hi_tee_drv_hal_mdelay() - delay helper function in resolution ms.
 * this function is base on the system secure timer, used for short dead loop
 *
 * @param ms   The time to delay.
 */
void hi_tee_drv_hal_mdelay(unsigned long msec);

/*
 * hi_tee_drv_hal_msleep() - sleep helper function in resolution ms.
 * this function is base on the system secure timer.
 * In trustedcore, actually it is a deap loop.
 * NOTE: the msec should be less than 1000.
 *
 * @param msec  The time to sleep.
 */
void hi_tee_drv_hal_msleep(unsigned long msec);

/*
 * hi_tee_drv_hal_mutex_init() - The mutex initialize function
 *
 * @param name   The name of the mutex
 * @param mutex  The pointer of the mutex which is to be initialized
 *
 * @return 0     The mutex is initialized successfully.
 */
int hi_tee_drv_hal_mutex_init(const char *name, struct hi_tee_hal_mutex *mutex);

/*
 * hi_tee_drv_hal_mutex_destroy() - The mutex destroy function
 * this function will only validate if the mutex is unlocked and no waiters, etc.
 *
 * @param mutex  The mutex which is to be destroyed
 * @return 0     destory mutex successfully.
 */
int hi_tee_drv_hal_mutex_destroy(struct hi_tee_hal_mutex *mutex);

/*
 * hi_tee_drv_hal_mutex_lock() - accuire the mutex lock
 *
 * @param mutex  The mutex to be accuired
 * @return 0     The mutex is locked successfully.
 */
int hi_tee_drv_hal_mutex_lock(struct hi_tee_hal_mutex *mutex);

/*
 * hi_tee_drv_hal_mutex_unlock() - release the mutex lock
 *
 * @param mutex  The mutex to be released
 * @return 0     The mutex is unlocked successfully.
 */
int hi_tee_drv_hal_mutex_unlock(struct hi_tee_hal_mutex *mutex);

/*
 * hi_tee_drv_hal_spin_lock_init() - spinlock init function
 *
 * @param lock   The lock to be initialized
 */
void hi_tee_drv_hal_spin_lock_init(struct hi_tee_hal_spinlock *lock);

/*
 * hi_tee_drv_hal_spin_lock() - NOTE: Not support in trustedcore
 */
void hi_tee_drv_hal_spin_lock(struct hi_tee_hal_spinlock *lock);

/*
 * hi_tee_drv_hal_spin_unlock() - NOTE: Not support in trustedcore
 */
void hi_tee_drv_hal_spin_unlock(struct hi_tee_hal_spinlock *lock);

/*
 * hi_tee_drv_hal_spin_lock_irqsave() - disable the interrupts
 *
 * @param lock          Not used in trustedcore
 *
 * @return irq status   The irq status which will be used for irqrestore
 */
unsigned int hi_tee_drv_hal_spin_lock_irqsave(struct hi_tee_hal_spinlock *lock);

/*
 * hi_tee_drv_hal_spin_lock_irqrestore() - restore the interrupts
 *
 * @param lock     Not used in trustedcore
 * @param status   The irq status to be restored
 */
void hi_tee_drv_hal_spin_unlock_irqrestore(struct hi_tee_hal_spinlock *lock, unsigned int status);

/*
 * hi_tee_drv_hal_malloc() - malloc heap memory
 *
 * @param size     The size of the memory to be allocated
 *
 * @return memory pointer   The allocated memory pointer
 * @return NULL             The allocation failed
 */
void *hi_tee_drv_hal_malloc(size_t size);

/*
 * hi_tee_drv_hal_free() - free the heap memory
 *
 * @param ptr   The pointer of the memory which is be freed.
 */
void hi_tee_drv_hal_free(void *ptr);

/*
 * hi_tee_drv_hal_remap() - map the specified memory into tee kernel
 * this function can only be used to map non secure memory.
 *
 * @param pa        The physic address of the memory to be mapped
 * @param size      The size of the memory to be mapped
 * @param is_secure The secure attribute of the mapping
 * @cached          The map cached attribute
 *
 * @return virtual address  The cpu virtual address of the map
 * @return NULL             The map failed for some reason
 */
void *hi_tee_drv_hal_remap(unsigned long long pa, size_t size, bool is_secure, bool cached);

/*
 * hi_tee_drv_hal_unmap() - unmap the specified memory from tee kernel
 * this function can only be used to unmap non secure memory.
 *
 * @param va     The virtual address of the memory to be unmapped
 * @param size   The size of the memory to be unmapped
 */
void hi_tee_drv_hal_unmap(void *va, size_t size);

/*
 * hi_tee_drv_hal_current_uuid() - get the current ta uuid
 *
 * @param uuid          The point which is used to return back the uuid
 *
 * @return TEE_SUCCESS  The function success
 * @return other value  The function failed
 */
int hi_tee_drv_hal_current_uuid(TEE_UUID *uuid);

/*
 * hi_tee_drv_hal_request_irq() - register irq handler
 *
 * @param irq       The irq number
 * @param handler   The irq callback handler
 * @param flag      The irq flag
 * @param dev       The param pass back to the handler
 *
 * @return TEE_SUCCESS  The irq is success registered
 * @return other value  The irq register failed for some reason
 */
int hi_tee_drv_hal_request_irq(unsigned int irq, void *handler, unsigned int flag, const void *dev);

/*
 * hi_tee_drv_hal_unregister_irq() - unregister irq
 *
 * @param irq  The irq to be unregistered
 */
void hi_tee_drv_hal_unregister_irq(unsigned int irq);

/*
 * hi_tee_drv_hal_raise_pi() - raise a ipi interrupts
 *
 * @param irq       The ipi(irq) number to raise
 */
void hi_tee_drv_hal_raise_pi(unsigned int irq);

/*
 * hi_tee_drv_hal_backtraces() - print the current callstack
 * used for debug perpose
 */
void hi_tee_drv_hal_backtraces(void);

/*
 * hi_tee_drv_hal_sys_reset() - reset the system
 * this function is used to harden the system, in some unexpected condition,
 * we need to reset the system to protect against attack
 */
void hi_tee_drv_hal_sys_reset(void);

/*
 * hi_tee_drv_hal_get_rodata_pa_range() - get the kernel and rodata physic memory range
 * this is used by the tzasc driver, kernel and rodata can be protect by tzasc as
 * readonly for cpu, this is more secure then only readonly by mmu.
 * Note: the text and kernel text should be physic contigous.
 *
 * @param base   The pointer of val which holds the start physic address
 * @param size   The pointer of val which holds the size of the size
 */
void hi_tee_drv_hal_get_rodata_pa_range(unsigned long long *base, unsigned long long *size);

/*
 * hi_tee_drv_hal_rng_generate() - generate random number
 * This functions is atomic, can be called from any context, mainly used for harden system
 * against fault inject attack.
 *
 * @param buffer  The pointer of val which holds the random number
 * @param len     The length of random nunber in bytes
 */
int hi_tee_drv_hal_rng_generate(void *buffer, size_t len);

/*
 * hi_tee_drv_hal_dcache_flush() - flush the dcache by va range
 *
 * @param va   The start va to be flushed
 * @param len  The length of the flush range
 */
void hi_tee_drv_hal_dcache_flush(void *va, size_t len);

/*
 * hi_tee_drv_hal_dcache_flush_all() - flush all the dcache
 * don't recommand use of the this function.
 */
void hi_tee_drv_hal_dcache_flush_all(void);

/*
 * hi_tee_drv_hal_dcache_invalidate() - NOTE: Not support in trustedcore
 */
void hi_tee_drv_hal_dcache_invalidate(void *va, size_t len);

/*
 * hi_tee_drv_hal_timer_init() - timer init function
 *
 * @param pstTevent The timer to be initialized
 */
int hi_tee_drv_hal_timer_init(hi_tee_hal_timer *pstTevent);

/*
 * hi_tee_drv_hal_timer_start() - timer start function
 * Note: timer currently is oneshot
 *
 * @param pstTevent The timer to be started
 */
int hi_tee_drv_hal_timer_start(hi_tee_hal_timer *pstTevent);

/*
 * hi_tee_drv_hal_timer_delete()- timer delete function
 *
 * @param pstTevent   The timer to be deleted
 */
int hi_tee_drv_hal_timer_delete(hi_tee_hal_timer *pstTevent);

/*
 * hi_tee_drv_hal_access_check() - check if the specified address range is valid
 *
 * @param addr   The start address to be checked
 * @param size   The size of the memory range to be checked
 */
bool hi_tee_drv_hal_access_check(const void *addr, size_t size);

/*
 * hi_tee_drv_hal_read_right_check() - check if the specfied address range is readable
 *
 * @param addr  The start address to be checked
 * @param size  The size of the memory range to be checked
 */
bool hi_tee_drv_hal_read_right_check(const void *addr, size_t size);

/*
 * hi_tee_drv_hal_write_right_check() - check if the specfied address range is writeable
 *
 * @param addr   The start address to be checked
 * @param size   The size of the memory range to be checked
 */
bool hi_tee_drv_hal_write_right_check(const void *addr, size_t size);

void hi_tee_drv_set_smmu_agent_msg_info(unsigned int msg_pid);

/*
 * hi_tee_drv_hal_agentcall() - call a REE side registered agent
 *
 * @param agent_id  The id of the called agent
 * @param buffer    The data buffer passed to the agent
 * @param len       The length of the buffer
 */
int hi_tee_drv_hal_agentcall(unsigned int agent_id, unsigned int send_msgid, void *buffer, size_t len);

/*
 * hi_tee_drv_hal_map_sg() - map a sglist of physic memory into tee/ta
 * this interface is only for smmu driver
 *
 * @param sg            The sg info to mapping
 * @param is_secure     The secure attribute of the mapping
 * @param cached        The cached attribute of the mapping
 * @param user_map      The map is userspace mapping or not
 * @param va            The return va of the function
 *
 * @return TEE_SUCESS   The function success
 * @return other value  The function failed for some reason
 */
int hi_tee_drv_hal_map_sg(struct hi_tee_hal_sg_info *sg, bool is_secure, bool cached, bool user_map, void *va);

/*
 * hi_tee_drv_hal_unmap_sg() - unmap a sglist of physic memory from tee/ta
 * this interface is only for smmu driver
 *
 * @param va            The return va of the function
 * @param size          The memory size of the whole sglist
 * @param is_secure     The secure attribute of the mapping
 * @param user_map      The map is userspace mapping or not
 *
 * @return TEE_SUCESS   The function success
 * @return other value  The function failed for some reason
 */
int hi_tee_drv_hal_unmap_sg(const void *va, size_t size, bool is_secure, bool user_map);

/*
 * hi_tee_drv_hal_permission_check() - check permission from tee/ta which call this drv
 * this interface is only for syscall
 *
 * @param crt_permissions     the permissions of current TA
 * @param check_permissions   the permissions to check
 *
 * @return TEE_SUCESS   Current TA has the permission
 * @return other value  Current TA does not have the permission
 */
int hi_tee_drv_hal_permission_check(unsigned long long crt_permissions, unsigned long long check_permissions);

/*
 * hi_tee_drv_hal_user_mmap() - map ta virt addr to drv
 * TA addr must map to drv if you want to use
 *
 * @param addr   The address where saves the ta address
 * @param size   The size of the memory range to be map
 *
 * @return TEE_SUCESS   The function success
 * @return other value  The function failed for some reason
 */
int hi_tee_drv_hal_user_mmap(void **addr, size_t size);

/*
 * hi_tee_drv_hal_user_munmap() - unmap the addr which maped by hi_tee_drv_hal_user_mmap
 * this interface must be call if had call hi_tee_drv_hal_user_mmap after the addr not be used
 *
 * @param addr   the addr need be unmap
 * @param size   The size of the memory range to be unmap
 *
 * @return TEE_SUCESS   The function success
 * @return other value  The function failed for some reason
 */
int hi_tee_drv_hal_user_munmap(void *addr, unsigned int size);

/*
 * hi_tee_drv_hal_module_register() - register a module function to handle system call
 *
 * @param module_id     The module id
 * @param fn            The system call handle function
 *
 * @return 0            Register successfully
 * @return other value  Register failed
 */
int hi_tee_drv_hal_module_register(const unsigned int module_id, hi_tee_hal_syscall fn);

#endif
