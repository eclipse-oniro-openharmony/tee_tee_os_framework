/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: snapshot for iTrustee elfloader loading phase
 * Create: 2021-12
 */

#include <snapshot.h>
#include <types.h>
#include <string.h>
#include <data.h>

#ifdef CONFIG_SNAPSHOT_RECORD

static void *get_snapshot_addr(void)
{
    return (void *)(TEE_SNAPSHOT_PADDR_START + BLOCK_DATA_SIZE * STATUS_TEE_BLOCK_ID);
}

void snapshot_start(void)
{
    map_devices(TEE_SNAPSHOT_PADDR_START);

    void *head_ptr = get_snapshot_addr();
    SNAPSHOT_BUF_HEAD *ptr_head = (SNAPSHOT_BUF_HEAD *)(uintptr_t)head_ptr;

    ptr_head->magic = SNAPSHOT_MAGIC;
    ptr_head->valid = STATUS_BLOCK_BOOT_VALID;
    ptr_head->block_id = STATUS_TEE_BLOCK_ID;
    ptr_head->arg_1 = 0x0;
    ptr_head->arg_2 = 0x0;
    ptr_head->exception_id = SNAPSHOT_BOOT_FAIL_ELFLOADER;
    ptr_head->expect_status = SNAPSHOT_EXCEPT_STATUS;
    ptr_head->current_status = 0x0;
}

void snapshot_record(uint32_t record)
{
    void *head_ptr = get_snapshot_addr();
    SNAPSHOT_BUF_HEAD *ptr_head = (SNAPSHOT_BUF_HEAD *)(uintptr_t)head_ptr;

    if (ptr_head->magic == SNAPSHOT_MAGIC)
        ptr_head->current_status = record;
}

void snapshot_finish(void)
{
    void *head_ptr = get_snapshot_addr();
    SNAPSHOT_BUF_HEAD *ptr_head = (SNAPSHOT_BUF_HEAD *)(uintptr_t)head_ptr;

    if (ptr_head->magic == SNAPSHOT_MAGIC) {
        ptr_head->valid = STATUS_BLOCK_BOOT_VALID;
        ptr_head->current_status = SNAPSHOT_RECORD_FINISH;
    }
}
#else
void snapshot_start(void)
{
}

void snapshot_record(uint32_t record)
{
    (void)record;
}

void snapshot_finish(void)
{
}
#endif

__attribute__((weak)) void boot_log_record(int finish_flag)
{
    (void)finish_flag;
}
