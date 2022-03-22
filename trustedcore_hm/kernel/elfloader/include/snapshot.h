/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: snapshot for iTrustee elfloader loading phase
 * Create: 2021-12
 */

#ifndef _SNAPSHOT_ELF_H_
#define _SNAPSHOT_ELF_H_

#include <types.h>

#define STATUS_BLOCK_BOOT_VALID         0x76U
#define STATUS_BLOCK_RUN_VALID          0x77U
#define STATUS_TEE_BLOCK_ID             0x4U
#define STATUS_BLOCK_INVALID            0x0U
#define SNAPSHOT_MAGIC                  0x6B6B6C6C
#define SNAPSHOT_EXCEPT_STATUS          0x3FFFFFFF
#define SNAPSHOT_BOOT_FAIL_ELFLOADER    0xA82A1000


/**
 *  the whole space is 512k, used for history data record
 *  status region use 31k
 *  the struct distribution is as follows:
 *  +-----------------------+
 *  | hdr log head(1k)      |
 *  +-----------------------+
 *  | boot log region(300k) |
 *  +-----------------------+
 *  | run log region(150k)  |
 *  +-----------------------+
 *  | hdr status head(1k)   |     status region:10           area:128                  block:24B
 *  +-----------------------+     +--------------------+     +-------------------+     +-----------------+
 *  | status region(30k)    |---->| first area(3k)     |---->| block(hboot)(24B) |---->| status_block    |
 *  +-----------------------+     +--------------------+     +-------------------+     +-----------------+
 *  | reserved(30k)         |     | ......             |     | ......            |
 *  +-----------------------+     +--------------------+     +-------------------+
 */
#define SNAPSHOT_DDR_BASE               0x31280000U
#define HDR_LOG_HEAD_SIZE               0x400U      // 1KB
#define LOG_BOOT_REGION_OFFSET          (SNAPSHOT_DDR_BASE + HDR_LOG_HEAD_SIZE)
#define LOG_BOOT_REGION_SIZE            0x4B000U    // 300KB
#define LOG_RUN_REGION_OFFSET           (LOG_BOOT_REGION_OFFSET + LOG_BOOT_REGION_SIZE)
#define LOG_RUN_REGION_SIZE             0x25800U    // 150KB
#define HDR_STATUS_HEAD_OFFSET          (LOG_RUN_REGION_OFFSET + LOG_RUN_REGION_SIZE)
#define HDR_STATUS_HEAD_SIZE            0x400U      // 1KB
#define SNAPSHOT_BLOCK_DATA_OFFSET      (HDR_STATUS_HEAD_OFFSET + HDR_STATUS_HEAD_SIZE)
#define BLOCK_DATA_SIZE                 24          // 24B

#define TEE_SNAPSHOT_PADDR_START        SNAPSHOT_BLOCK_DATA_OFFSET

enum SNAPSHOT_ELFLOADER_INDEX {
    SNAPSHOT_RECORD_LOADER_INIT = 0x31000001,
    SNAPSHOT_RECORD_ASLR_INIT,
    SNAPSHOT_RECORD_PROCESS_KERNEL,
    SNAPSHOT_RECORD_PROCESS_BOOT_APPS,
    SNAPSHOT_RECORD_INIT_KERNEL_VSPACE,
    SNAPSHOT_RECORD_SMP_BOOT,
    SNAPSHOT_RECORD_BOOT_KERNEL,
};

#define SNAPSHOT_RECORD_FINISH              0x3fffffff

typedef struct snapshot_buf_head {
    uint32_t magic;
    uint8_t valid; /* STATUS_BLOCK_BOOT_VALID, STATUS_BLOCK_RUN VALID */
    uint8_t block_id;
    uint8_t arg_1;
    uint8_t arg_2;
    uint32_t exception_id;
    uint32_t expect_status;
    uint32_t current_status;
    uint32_t reserve;
} SNAPSHOT_BUF_HEAD;

void snapshot_start(void);
void snapshot_record(uint32_t record);
void snapshot_finish(void);

#endif
