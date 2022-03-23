/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee drv os hal func test
 * Author: Hisilicon
 * Created: 2020-04-30
 */

#include "tee_drv_demo_func_test.h"

static void tee_drv_demo_test_remap_and_unmap(unsigned long long addr, unsigned int data, bool is_secure)
{
    void *virt = NULL;
    const size_t size = TEST_SIZE_1M;
    int ret;

    /* secure  */
    virt = hi_tee_drv_hal_remap(addr, size, is_secure, true);
    if (virt == NULL) {
        test_printf("hi_tee_drv_hal_remap failed!\n\n");
        return;
    }

    ret = memset_s(virt, size, data, size);
    if (ret != EOK) {
        test_printf("memset_s failed!\n\n");
        return;
    }
    test_printf("hi_tee_drv_hal_dcache_flush start\n");
    hi_tee_drv_hal_dcache_flush(virt, size);

    test_printf("hi_tee_drv_hal_dcache_invalidate start\n");
    hi_tee_drv_hal_dcache_invalidate(virt, size);   /* NULL, Not support in trustedcore */

    test_printf("hi_tee_drv_hal_dcache_flush_all start\n");
    hi_tee_drv_hal_dcache_flush_all();
    test_printf("vir:0x%x  val:0x%x\n", (unsigned long *)virt, *(unsigned long *)virt);

    hi_tee_drv_hal_unmap(virt, size);
    test_printf("%s map/unmap successfully\n\n", is_secure ? "secure" : "nosec");
}

static void tee_drv_demo_test_addr_translate(void)
{
    void *virt = NULL;
    unsigned long long phys;

    virt = hi_tee_drv_hal_phys_to_virt(TEST_IO_ADDR);
    if (virt == NULL) {
        test_printf("hi_tee_drv_hal_phys_to_virt failed!\n\n");
        return;
    }
    test_printf("virt:0x%x  val:0x%x \n", virt, *(unsigned int *)virt);

    phys = hi_tee_drv_hal_virt_to_phys(virt);
    if (phys == 0) {
        test_printf("hi_tee_drv_hal_virt_to_phys failed!\n\n");
        return;
    }
    test_printf("virt:0x%x  phys:0x%llx \n", virt, phys);
    test_printf("phys to virt and virt to phys successfully!\n\n");
}

static void tee_drv_demo_test_mem_malloc_and_free(void)
{
    unsigned char *buf[3] = {NULL, NULL, NULL}; /* alloc 3 buf */
    unsigned char *ret_buf = NULL;
    const size_t size = TEST_SIZE_4K;
    int i, j;
    int ret;

    for (i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
        buf[i] = (unsigned char *)hi_tee_drv_hal_malloc(size);
        if (buf[i] == NULL) {
            test_printf("hi_tee_drv_hal_malloc[%d] failed!\n", i);
            goto out;
        }
    }

    ret = memset_s(buf[0], size, TEST_DATA1, size);
    if (ret != EOK) {
        test_printf("memset_s failed!\n");
        goto out;
    }

    ret_buf = hi_tee_drv_hal_asm_memmove(buf[1], buf[0], size);
    if (ret_buf == NULL) {
        test_printf("hi_tee_drv_hal_asm_memmove failed!\n");
        goto out;
    }
    ret_buf = hi_tee_drv_hal_asm_memcpy(buf[2], buf[0], size); /* index 2 */
    if (ret_buf == NULL) {
        test_printf("hi_tee_drv_hal_asm_memcpy failed!\n");
        goto out;
    }

    for (j = 0; j < i; j++) {
        test_printf("buf[%d]:0x%llx  *buf[%d]:0x%llx \n", j, (unsigned long long)(uintptr_t)buf[j],
                    j, *(unsigned long long *)buf[j]);
    }
    test_printf("cpy and memmove successfully!\n");

out:
    for (j = 0; j < i; j++) {
        hi_tee_drv_hal_free(buf[j]);
    }
    if (j == sizeof(buf) / sizeof(buf[0])) {
        test_printf("malloc and free successfully!\n");
    }
    hi_tee_drv_hal_printf("\n");
}

static void tee_drv_demo_test_mem_check(void)
{
    unsigned char *buf = NULL;
    bool check = false;
    const size_t size = TEST_SIZE_4K;

    buf = (unsigned char *)hi_tee_drv_hal_malloc(size);
    if (buf == NULL) {
        test_printf("hi_tee_drv_hal_malloc failed!\n\n");
        return;
    }

    check = hi_tee_drv_hal_access_check(buf, size);
    if (!check) {
        test_printf("buf[0x%llx] invalid!\n", (unsigned long long)(uintptr_t)buf);
    }

    check = hi_tee_drv_hal_read_right_check(buf, size);
    if (!check) {
        test_printf("buf[0x%llx] has no read access!\n", (unsigned long long)(uintptr_t)buf);
    }

    check = hi_tee_drv_hal_write_right_check(buf, size);
    if (!check) {
        test_printf("buf[0x%llx] has no write access!\n", (unsigned long long)(uintptr_t)buf);
    }

    hi_tee_drv_hal_free(buf);
    test_printf("mem check successfully!\n\n");
}

static void tee_drv_demo_test_mem(void)
{
    tee_drv_demo_test_remap_and_unmap(TEST_SEC_MMZ_ADDR, TEST_DATA1, true);
    tee_drv_demo_test_remap_and_unmap(TEST_NOSEC_MEM_ADDR, TEST_DATA2, false);
    tee_drv_demo_test_addr_translate();
    tee_drv_demo_test_mem_malloc_and_free();
    tee_drv_demo_test_mem_check();

    test_printf("mem test successfully\n\n");
}

static void tee_drv_demo_test_mutex_lock(void)
{
#define MUTEX_LOCK_TEST_TIME    3
    struct hi_tee_hal_mutex mutex;
    int ret;
    int i;

    ret = hi_tee_drv_hal_mutex_init("lock_test", &mutex);
    if (ret) {
        test_printf("hi_tee_drv_hal_mutex_init failed!\n\n");
        return;
    }

    test_printf("hi_tee_drv_hal_mutex_lock start\n");
    ret = hi_tee_drv_hal_mutex_lock(&mutex);
    if (ret) {
        test_printf("mutex lock failed!\n\n");
        return;
    }
    test_printf("hi_tee_drv_hal_mutex_lock end\n");

    test_printf("hi_tee_drv_hal_mutex_unlock start\n");
    for (i = 0; i < MUTEX_LOCK_TEST_TIME; i++) {
        ret = hi_tee_drv_hal_mutex_unlock(&mutex);
        if (ret) {
            test_printf("hi_tee_drv_hal_mutex_unlock[%d] failed!\n\n", i);
            return;
        }
    }
    test_printf("hi_tee_drv_hal_mutex_unlock end\n");

    test_printf("hi_tee_drv_hal_mutex_destroy start\n");
    for (i = 0; i < MUTEX_LOCK_TEST_TIME; i++) {
        ret = hi_tee_drv_hal_mutex_destroy(&mutex);
        if (ret) {
            test_printf("hi_tee_drv_hal_mutex_destroy[%d] failed!\n\n", i);
            return;
        }
    }
    test_printf("hi_tee_drv_hal_mutex_destroy end\n");

    test_printf("os_hal_mutex_lock successfully!\n\n");
}

static void tee_drv_demo_test_spin_lock(void)
{
#define SPIN_LOCK_TEST_TIME    4
    struct hi_tee_hal_spinlock lock;
    int i;

    hi_tee_drv_hal_spin_lock_init(&lock);   /* NULL */
    hi_tee_drv_hal_spin_lock(&lock);        /* NULL */
    hi_tee_drv_hal_spin_unlock(&lock);      /* NULL */

    test_printf("hi_tee_drv_hal_spin_lock_irqsave 1 \n");
    hi_tee_drv_hal_spin_lock_irqsave(&lock);
    test_printf("hi_tee_drv_hal_spin_lock_irqsave 2 \n");
    hi_tee_drv_hal_spin_lock_irqsave(&lock);

    for (i = 0; i < SPIN_LOCK_TEST_TIME; i++) {
        test_printf("hi_tee_drv_hal_spin_unlock_irqrestore %d \n", i);
        hi_tee_drv_hal_spin_unlock_irqrestore(&lock, 0);
    }
    test_printf("os_hal_spin_lock successfully!\n\n");
}

static void tee_drv_demo_test_delay(void)
{
    unsigned long long time_start, time_end, time;

    time_start = hi_tee_drv_hal_get_system_time_in_us();
    hi_tee_drv_hal_udelay(TEST_TIME_US_20MS); 
    time_end = hi_tee_drv_hal_get_system_time_in_us();
    time = time_end - time_start;
    test_printf("time_start:%lld  time_end:%lld  udelay_time:%lld \n", time_start, time_end, time);

    time_start = hi_tee_drv_hal_get_system_time_in_us();
    hi_tee_drv_hal_mdelay(TEST_TIME_MS_500MS);
    time_end = hi_tee_drv_hal_get_system_time_in_us();
    time = time_end - time_start;
    test_printf("time_start:%lld  time_end:%lld  mdelay_time:%lld \n", time_start, time_end, time);

    time_start = hi_tee_drv_hal_get_system_time_in_us();
    hi_tee_drv_hal_msleep(TEST_TIME_MS_200MS);
    time_end = hi_tee_drv_hal_get_system_time_in_us();
    time = time_end - time_start;
    test_printf("time_start:%lld  time_end:%lld  msleep_time:%lld \n", time_start, time_end, time);

    time_start = hi_tee_drv_hal_get_system_time_in_us();
    time = hi_tee_drv_hal_get_system_time_in_us();
    time_end = hi_tee_drv_hal_get_system_time_in_us();
    time = time_end - time_start;
    test_printf("time_start:%lld  time_end:%lld  func_spend_time:%lld \n", time_start, time_end, time);
    test_printf("get time and delay and sleep successfully!\n\n");
}

static unsigned int tee_drv_demo_test_timer_handle(unsigned long args);

#define TEST_TIMER_TIMES    5
static volatile unsigned int g_times;
hi_tee_hal_timer g_timer = {
    .handler = tee_drv_demo_test_timer_handle,
    .expires = TEST_TIME_US_20MS,
    .data    = 12, /* 12, data */
    .timer   = NULL,
};

static unsigned int tee_drv_demo_test_timer_handle(unsigned long args)
{
    int ret;

    test_printf("timer test %d args = %d\n", g_times, args);
    if (g_times > TEST_TIMER_TIMES) {
        test_printf("timer test finish\n");
        return 0;
    }

    g_times++;
    g_timer.data = g_times;
    ret = hi_tee_drv_hal_timer_start(&g_timer);
    if (ret) {
        test_printf("hi_tee_drv_hal_timer_start[%d] failed\n", g_times);
    }
    return 0;
}


static void tee_drv_demo_test_timer(void)
{
    int ret;

    ret = hi_tee_drv_hal_timer_init(&g_timer);
    if (ret) {
        test_printf("hi_tee_drv_hal_timer_init failed\n\n");
        return;
    }

    g_times = 1;
    ret = hi_tee_drv_hal_timer_start(&g_timer);
    if (ret) {
        test_printf("hi_tee_drv_hal_timer_start failed\n\n");
        goto out;
    }

    while (g_times <= TEST_TIMER_TIMES) {
        hm_yield(); /* enable the CPU can be dispatched */
    }

    test_printf("timer test success!\n\n");

out:
    ret = hi_tee_drv_hal_timer_delete(&g_timer);
    if (ret) {
        test_printf("hi_tee_drv_hal_timer_delete failed\n\n");
        hi_tee_drv_hal_sys_reset();
    }
}

static void tee_drv_demo_test_time(void)
{
    tee_drv_demo_test_delay();
    tee_drv_demo_test_timer();
    test_printf("time func test successfully!\n\n");
}

static void tee_drv_demo_test_ta_uuid(void)
{
    TEE_UUID uuid;
    int ret;

    ret = memset_s(&uuid, sizeof(TEE_UUID), 0, sizeof(TEE_UUID));
    if (ret != EOK) {
        test_printf("memset_s failed\n\n");
        return;
    }

    ret = hi_tee_drv_hal_current_uuid(&uuid);
    if (ret) {
        test_printf("hi_tee_drv_hal_current_uuid failed\n\n");
        return;
    }
}

static void tee_drv_demo_test_random(void)
{
#define RNG_TEST_MAX_TIME    20
    unsigned long long rng = 0;
    int i;
    int ret;

    ret = hi_tee_drv_hal_rng_generate(&rng, sizeof(rng));
    if (ret) {
        test_printf("hi_tee_drv_hal_rng_generate failed!\n\n");
        return;
    }
    test_printf("get rng: 0x%llx\n", rng);

    for (i = 0; i < RNG_TEST_MAX_TIME; i++) {
        ret = hi_tee_drv_hal_rng_generate(&rng, sizeof(rng));
        if (ret) {
            test_printf("hi_tee_drv_hal_rng_generate[%d] failed!\n\n", i);
            continue;
        }
        break;
    }
    test_printf("get rng[%d]:0x%llx\n\n", i, rng);
}

static void tee_drv_demo_test_irq(void)
{
    test_printf("dump tzasc register:\n");
    hi_tee_drv_hal_raise_pi(TEST_IRQ);

    test_printf("unregister tzasc irq\n");
    hi_tee_drv_hal_unregister_irq(TEST_IRQ);

    test_printf("here will dump tzasc register failed\n");
    hi_tee_drv_hal_raise_pi(TEST_IRQ);

    test_printf("print the current callstack:\n");
    hi_tee_drv_hal_backtraces();

    test_printf("the tzasc irq config has been damaged, reset the system!\n");
    hi_tee_drv_hal_sys_reset();
}

void tee_drv_demo_func_test(unsigned int cmd)
{
    switch (cmd) {
        case 0: /* 0, test cmd */
            tee_drv_demo_test_mem();
            tee_drv_demo_test_mutex_lock();
            tee_drv_demo_test_spin_lock();
            tee_drv_demo_test_time();
            tee_drv_demo_test_ta_uuid();
            tee_drv_demo_test_random();
            tee_drv_demo_test_irq();  /* will reset system, test at last */
            break;
        default:
            break;
    }
}

