/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#include "hisi_hdcp.h"
#include <drv_mem.h> // tee_mmu_check_access_rights
#include "tee_defines.h"
#include "mem_page_ops.h"

#define FILENAME_LENGTH    64
#define FILE_NAME_LEN_MAX    255

#define udelay(usec) do{\
        int i;\
        for(i=0;i<1000*usec;i++){asm("nop");};\
    }while(0)

extern void uart_printf_func(const char *fmt, ...);

static int hdcp13_key_set(hdcp13_key_t* key)
{
    if (key == NULL){
        uart_printf_func("hdcp13_key_set the key is NULL\n");
        return -1;
    }
    writel(key->key_l, HDCP_BASE_ADDR + HDCP13_KEY1_OFFSET);
    writel(key->key_h, HDCP_BASE_ADDR + HDCP13_KEY0_OFFSET);

    return 0;
}

static int hdcp22_trng_init(void)
{
    writel(0x000a0100, HDCP_BASE_ADDR + HDCP22_TRNG_SMODE_OFFSET);
    writel(0x00, HDCP_BASE_ADDR + HDCP22_TRNG_MODE_OFFSET);
    writel(0x02, HDCP_BASE_ADDR + HDCP22_TRNG_RESEED_OFFSET);
    writel(0x01, HDCP_BASE_ADDR + HDCP22_TRNG_RESEED_OFFSET);
    writel(0x03, HDCP_BASE_ADDR + HDCP22_TRNG_ISTAT_OFFSET);

    return 0;
}

static int hdcp22_duk_set(hdcp22_key_t* duk)
{
    if (duk == NULL){
        uart_printf_func("hdcp22_duk_set duk is NULL\n");
        return -1;
    }
    writel(duk->key_l, HDCP_BASE_ADDR + HDCP22_DUK0_OFFSET);
    writel(duk->key_m1, HDCP_BASE_ADDR + HDCP22_DUK1_OFFSET);
    writel(duk->key_m2, HDCP_BASE_ADDR + HDCP22_DUK2_OFFSET);
    writel(duk->key_h, HDCP_BASE_ADDR + HDCP22_DUK3_OFFSET);

    return 0;
}

static int hdcp22_pkf_set(hdcp22_key_t* kpf)
{
    if (kpf == NULL){
        uart_printf_func("hdcp22_pkf_set kpf is NULL\n");
        return -1;
    }
    writel(kpf->key_l, HDCP_BASE_ADDR + HDCP22_KPF0_OFFSET);
    writel(kpf->key_m1, HDCP_BASE_ADDR + HDCP22_KPF1_OFFSET);
    writel(kpf->key_m2, HDCP_BASE_ADDR + HDCP22_KPF2_OFFSET);
    writel(kpf->key_h, HDCP_BASE_ADDR + HDCP22_KPF3_OFFSET);

    return 0;
}

int hdcp13_key_all_set(hdcp13_all_key_t *key_all)
{
    uint32_t dpk13_size = 0;
    if(key_all == NULL){
        uart_printf_func("hdcp13_key_all_set the point is NULL\n");
        return -1;
    }

    if(hdcp13_key_set(&(key_all->aksv))){
        uart_printf_func("hdcp13 aksv write failed\n");
        return -1;
    }

    udelay(10);
    writel(0x00, HDCP_BASE_ADDR + HDCP13_SEED_ENABLE);

    while (dpk13_size < 40) {
        if(hdcp13_key_set(&(key_all->dpk[dpk13_size]))){
            uart_printf_func("hdcp13 dpk write failed\n");
            return -1;
        }
        udelay(10);
        dpk13_size++;
    }

    return 0;
}

int hdcp22_key_set(hdcp22_key_t* duk, hdcp22_key_t* kpf)
{
    if((duk == NULL) || (kpf == NULL)){
        uart_printf_func("hdcp22_key_set the point is NULL\n");
        return -1;
    }
    hdcp22_pkf_set(kpf);
    hdcp22_duk_set(duk);
    hdcp22_trng_init();

    return 0;
}

int hdcp_dp_enable(unsigned int dp_flag)
{
    uint32_t temp;
    if(dp_flag > 1){
        uart_printf_func("hdcp_dp_enable the param is invalid\n");
        return -1;
    }
    temp = readl(HDCP_BASE_ADDR + HDCP_DPC_SEC_ENABLE);
    temp = (temp & (~0x40)) | (dp_flag << 6);
    writel(temp, HDCP_BASE_ADDR + HDCP_DPC_SEC_ENABLE);

    return 0;
}

int hdcp_get_value(unsigned int offset)
{
    if (tee_mmu_check_access_rights(ACCESS_READ, HDCP_BASE_ADDR + offset, sizeof(int))) {
        uart_printf_func("ERROR!!!!, it seems the input buffer read denied line is %d\n", __LINE__);
        return -1;
    }
    if (offset > HDCP_OFFSET_MAX) {
        uart_printf_func("ERROR!!!,the offset is out of range, and line is %d\n", __LINE__);
        return -1;
    }
    return readl(HDCP_BASE_ADDR + offset);
}

int hdcp_set_reg(unsigned int reg_value, unsigned int offset)
{
    if (tee_mmu_check_access_rights(ACCESS_WRITE, HDCP_BASE_ADDR + offset, sizeof(int))) {
        uart_printf_func("ERROR!!!!, it seems the input buffer write denied line is %d\n", __LINE__);
        return -1;
    }
    if (offset > HDCP_OFFSET_MAX) {
        uart_printf_func("ERROR!!!,the offset is out of range, and line is %d\n", __LINE__);
        return -1;
    }
    writel(reg_value, HDCP_BASE_ADDR + offset);
    return 0;
}



