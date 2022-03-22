/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secmem driver
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-08-31
 */
#include "secmem_core_api.h"
#include <stdbool.h>
#include <tee_log.h>
#include "drv_fwk.h"

#define MTK_SIP_TEE_MPU_PERM_SET_AARCH32 0x82000031

static struct sec_mem_info g_secmem[T_MPU_REQ_ORIGIN_TEE_ZONE_MAX];

void secmem_core_init(void)
{
    uint32_t i;
    for (i = 0; i < T_MPU_REQ_ORIGIN_TEE_ZONE_MAX; i++) {
        g_secmem[i].paddr = 0;
        g_secmem[i].size = 0;
        g_secmem[i].used = false;
    }
}

#define LOW_16BIT_MASK 0x0000FFFFU
#define ZONE_ID_OFFSET_BIT 16U
uint32_t get_zone_info(uint32_t zone_id, uint32_t op)
{
    uint32_t zone_info;

    zone_info = (op & LOW_16BIT_MASK);
    zone_info |= ((zone_id & LOW_16BIT_MASK) << ZONE_ID_OFFSET_BIT);

    return zone_info;
}

/*
 * Cut lower 16-bits for 64KB alignment.
 * So that we can use 32-bit variable to carry 48-bit physical address range.
 */
#define MPU_PHYSICAL_ADDR_SHIFT_BITS 16U
uint32_t get_encoded_phys_addr(uint64_t addr)
{
    return (addr >> MPU_PHYSICAL_ADDR_SHIFT_BITS);
}

static bool is_valid_zone(uint32_t zone)
{
    if ((zone < T_MPU_REQ_ORIGIN_TEE_ZONE_MAX) &&
        (zone >= T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT1))
        return true;

    return false;
}

#define SIZE_64K 0x00010000U
static bool is_valid_addr(uint64_t addr)
{
    if (addr == 0)
        return false;

    if ((addr % SIZE_64K) != 0)
        return false;

    return true;
}

static bool is_valid_size(uint32_t size)
{
    if (size == 0)
        return false;

    if (size < SIZE_64K)
        return false;

    if ((size % SIZE_64K) != 0)
        return false;

    return true;
}

static bool is_valid_paddr_region_enable(uint64_t paddr, uint32_t size)
{
    int32_t i;

    for (i = 0; i < T_MPU_REQ_ORIGIN_TEE_ZONE_MAX; i++) {
        if (!g_secmem[i].used)
            continue;
        if ((paddr + size) <= g_secmem[i].paddr)
            continue;
        if (paddr >= g_secmem[i].paddr + g_secmem[i].size)
            continue;
        break;
    }

    if (i != T_MPU_REQ_ORIGIN_TEE_ZONE_MAX) {
        tloge("region is overlap\n");
        return false;
    }

    return true;
}

static bool is_valid_paddr_region_disable(enum tee_mpu_req_zone_id zone_id, uint64_t paddr, uint32_t size)
{
    if (!g_secmem[zone_id].used) {
        tloge("disable zone_id:%d not used\n", zone_id);
        return false;
    }

    if (g_secmem[zone_id].paddr != paddr || g_secmem[zone_id].size != size) {
        tloge("disable paddr region invalid\n");
        return false;
    }
    return true;
}

static bool is_valid_paddr_region(enum tee_mpu_req_zone_id zone_id,
    uint64_t paddr, uint32_t size, uint32_t enable)
{
    if (enable == 0)
        return is_valid_paddr_region_disable(zone_id, paddr, size);

    if (!is_valid_addr(paddr) || !is_valid_size(size)) {
        tloge("paddr or size is invalid\n");
        return false;
    }

    if (g_secmem[zone_id].used) {
        tloge("enable zone id:%d is used\n", zone_id);
        return false;
    }

    return is_valid_paddr_region_enable(paddr, size);
}

static bool is_addr_param_valid(uint64_t start_addr, uint64_t end_addr)
{
    if (start_addr >= end_addr) {
        tloge("start_addr is larger than end_addr\n");
        return false;
    }

    if (end_addr - start_addr >= UINT32_MAX) {
        tloge("addr range is invalid\n");
        return false;
    }

    return true;
}

uint32_t dr_securemem_set(enum tee_mpu_req_zone_id zone_id, uint64_t start_addr,
    uint64_t end_addr, uint32_t enable)
{
    uint32_t zone_size;
    uint32_t zone_info;
    uint32_t encoded_addr;
    uint32_t api_ret;
    uint32_t smc_ret;

    if (!is_addr_param_valid(start_addr, end_addr)) {
        tloge("addr range is invalid\n");
        return MEM_ERROR_SMC_MPU_INVALID_ADDR_OR_SIZE;
    }

    zone_size = end_addr - start_addr;

    if (!is_valid_zone(zone_id)) {
        tloge("Invalid zone: %d\n", zone_id);
        return MEM_ERROR_SMC_MPU_INVALID_ZONE;
    }

    if (!is_valid_paddr_region(zone_id, start_addr, zone_size, enable)) {
        tloge("Invalid addr or size! 0x%x - 0x%x (0x%x)\n",
            (uint32_t)start_addr, (uint32_t)end_addr, zone_size);
        return MEM_ERROR_SMC_MPU_INVALID_ADDR_OR_SIZE;
    }

    zone_info = get_zone_info(zone_id, enable);
    encoded_addr = get_encoded_phys_addr(start_addr);

    api_ret = msee_smc_call(MTK_SIP_TEE_MPU_PERM_SET_AARCH32, encoded_addr,
                            zone_size, zone_info, &smc_ret);
    if (api_ret != 0) {
        tloge("SMC API failed: 0x%x\n", api_ret);
        return MEM_ERROR_SMC_CALL_API_FAIL;
    } else if (smc_ret != 0) {
        tloge("SMC Set failed: 0x%x\n", smc_ret);
        return MEM_ERROR_SMC_CALL_RESULT_FAIL;
    }

    if (enable != 0) {
        g_secmem[zone_id].paddr = start_addr;
        g_secmem[zone_id].size = zone_size;
        g_secmem[zone_id].used = true;
    } else {
        g_secmem[zone_id].paddr = 0;
        g_secmem[zone_id].size = 0;
        g_secmem[zone_id].used = false;
    }

    tlogd("SMC passed!\n");

    return MEM_API_OK;
}

bool dr_securemem_query(enum tee_mpu_req_zone_id zone_id, uint64_t start_addr, uint64_t end_addr)
{
    if (!is_valid_zone(zone_id) || !g_secmem[zone_id].used) {
        tloge("invalid zone_id:%d\n", zone_id);
        return false;
    }

    if (!is_addr_param_valid(start_addr, end_addr)) {
        tloge("invalid addr range\n");
        return false;
    }

    if ((start_addr >= g_secmem[zone_id].paddr) && (end_addr <= g_secmem[zone_id].paddr + g_secmem[zone_id].size))
        return true;

    return false;
}

uint32_t dr_securemem_getphy(enum tee_mpu_req_zone_id zone_id, uint64_t handle, uint64_t *phy_addr)
{
    (void)zone_id;
    (void)handle;
    (void)phy_addr;

    tloge("get phy addr api not support\n");

    return -1;
}
