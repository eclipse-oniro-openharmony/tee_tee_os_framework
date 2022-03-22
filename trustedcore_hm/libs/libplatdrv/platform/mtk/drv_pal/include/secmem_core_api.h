/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secmem drv api header
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-08-31
 */
#ifndef DRV_PAL_SECMEM_CORE_API_H
#define DRV_PAL_SECMEM_CORE_API_H

#include <stdbool.h>
#include <stdint.h>

enum tee_mpu_req_zone_id {
    T_MPU_REQ_ORIGIN_TEE_ZONE_SVP = 0,
    T_MPU_REQ_ORIGIN_TEE_ZONE_TUI = 1,
    T_MPU_REQ_ORIGIN_TEE_ZONE_WFD = 2,
    T_MPU_REQ_ORIGIN_TEE_ZONE_SDSP_SHARED_VPU_TEE = 3,
    T_MPU_REQ_ORIGIN_TEE_ZONE_2D_FR = 4,
    T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT1 = 5,
    T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT2 = 6,
    T_MPU_REQ_ORIGIN_TEE_ZONE_EID = 7,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R1 = 8,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R2 = 9,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R3 = 10,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R4 = 11,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R5 = 12,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R6 = 13,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R7 = 14,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R8 = 15,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R9 = 16,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R10 = 17,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R11 = 18,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R12 = 19,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R13 = 20,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R14 = 21,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R15 = 22,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R16 = 23,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R17 = 24,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R18 = 25,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R19 = 26,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R20 = 27,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R21 = 28,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R22 = 29,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R23 = 30,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R24 = 31,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R25 = 32,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R26 = 33,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R27 = 34,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R28 = 35,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R29 = 36,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R30 = 37,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R31 = 38,
    T_MPU_REQ_ORIGIN_TEE_ZONE_ALGO_R32 = 39,
    T_MPU_REQ_ORIGIN_TEE_ZONE_MAX = 40,

    T_MPU_REQ_ORIGIN_ZONE_INVALID = 0x7FFFFFFF
};

enum mem_api_status {
    MEM_API_OK = 0x0,
    MEM_ERROR_SMC_MPU_INVALID_ZONE = 0x1,
    MEM_ERROR_SMC_MPU_INVALID_ADDR_OR_SIZE = 0x2,
    MEM_ERROR_SMC_CALL_API_FAIL = 0x3,
    MEM_ERROR_SMC_CALL_RESULT_FAIL = 0x4,
    MEM_ERROR_MAX = 0x7FFFFFFF /* force enum to use 32 bits */
};

struct sec_mem_info {
    uint64_t paddr;
    uint32_t size;
    bool used;
};

void secmem_core_init(void);
uint32_t dr_securemem_set(enum tee_mpu_req_zone_id zone_id, uint64_t start_addr,
    uint64_t end_addr, uint32_t enable);
bool dr_securemem_query(enum tee_mpu_req_zone_id zone_id, uint64_t start_addr, uint64_t end_addr);
uint32_t dr_securemem_getphy(enum tee_mpu_req_zone_id zone_id, uint64_t handle, uint64_t *phy_addr);

#endif
