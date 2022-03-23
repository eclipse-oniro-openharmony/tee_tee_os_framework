/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include <product_config.h>
#include <osl_balong.h>
#include <drv_mem.h>
#include <drv_module.h>
#include <hm_mman_ext.h>
#include <mem_ops_ext.h>
#include <bsp_modem_call.h>
#include <bsp_memory_layout.h>
#include <securec.h>
#include <secboot.h>

#define SOCP_REG_ENCSRC_BUFWPTR(m) (0x300 + (m)*0x40)
#define SOCP_REG_ENCSRC_BUFRPTR(m) (0x304 + (m)*0x40)
#define SOCP_REG_ENCSRC_BUFADDR_L(m) (0x308 + (m)*0x40)
#define SOCP_REG_ENCSRC_BUFADDR_H(m) (0x30C + (m)*0x40)
#define SOCP_REG_ENCSRC_BUFDEPTH(m) (0x310 + (m)*0x40)
#define SOCP_REG_ENCSRC_BUFCFG(m) (0x314 + (m)*0x40)
#define SOCP_REG_ENCSRC_RDQWPTR(m) (0x318 + (m)*0x40)
#define SOCP_REG_ENCSRC_RDQRPTR(m) (0x31c + (m)*0x40)
#define SOCP_REG_ENCSRC_RDQADDR_L(m) (0x320 + (m)*0x40)
#define SOCP_REG_ENCSRC_RDQADDR_H(m) (0x324 + (m)*0x40)
#define SOCP_REG_ENCSRC_RDQCFG(m) (0x328 + (m)*0x40)
#define SOCP_REG_ENCDST_BUFCFG(channel) (0x131c + 0x40 * (channel))
#define SOCP_REG_SIZE 0x2000

#define MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD 0x56781234
#define MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD 0x78563412
#define MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD 0x12345678
#define MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD 0x34127856
#define MODEM_SEC_DUMP_RETRANS_LOG_CMD 0xDEF09ABC

#define DUMP_SEC_TRANS_SIGNLE_MAX_SIZE 0xFFF0
#define DUMP_SEC_TRANS_FILE_MAGIC 0x5678FEDC

#define SEC_DUMP_ADDRL(addr) ((u64)(addr)&0xFFFFFFFF)
#define SEC_DUMP_ADDRH(addr) (((u64)(addr) >> 32) & 0xFFFFFFFF)
#define SOCP_SRC_CFG_DEFAULT(dst_chnl) (0x00000e04 | (((dst_chnl)&0x3) << 4))

#ifndef BIT
#define BIT(n) (1 << (n))
#endif

#define DUMP_ATTR_SAVE_DEFAULT BIT(0)
#define DUMP_ATTR_SAVE_EXTRA_MDM BIT(1)
#define DUMP_ATTR_SAVE_MBB BIT(2)
#define DUMP_ATTR_SAVE_PHONE BIT(3)
#define DUMP_ATTR_SAVE_MINIDUMP BIT(4)
#define DUMP_ATTR_SAVE_FULLDUMP BIT(5)
#define DUMP_ATTR_SAVE_FEATURE_LTEV BIT(6)

#define DUMP_ATTR_DECODE_DEFAULT(attr) ((attr)&DUMP_ATTR_SAVE_DEFAULT)
#define DUMP_ATTR_DECODE_PLAT(attr) ((attr) & (DUMP_ATTR_SAVE_EXTRA_MDM | DUMP_ATTR_SAVE_MBB | DUMP_ATTR_SAVE_PHONE))
#define DUMP_ATTR_DECODE_DUMP_LEVEL(attr) ((attr) & (DUMP_ATTR_SAVE_MINIDUMP | DUMP_ATTR_SAVE_FULLDUMP))
#define DUMP_ATTR_DECODE_FEATURE(attr) ((attr)&DUMP_ATTR_SAVE_FEATURE_LTEV)

#define DUMP_MATCH_ATTRIBUTE(except_attr, curr_attr) (((except_attr) & (curr_attr)) == (except_attr))
#define DUMP_EXISTS_ATTRIBUTE(except_attr, curr_attr) (((except_attr) & (curr_attr)) != 0)
#define sec_dump_print(fmt, ...) uart_printf_func("[sec_dump]:" fmt, ##__VA_ARGS__)

typedef enum {
    DUMP_SEC_MDM_DDR = 0,              /**< TSP核使用的DDR */
    DUMP_SEC_SEC_SHARED = 1,           /**< 安全共享内存 */
    DUMP_SEC_LPHY_DUMP = 2,            /**< LPHY日志 */
    DUMP_SEC_NRPHY_DUMP = 3,           /**< NPHY 日志 */
    DUMP_SEC_EASYRF_DUMP = 4,          /**< EASYRF 日志 */
    DUMP_SEC_NRCCPU_DDR = 5,           /**< NRCCPU使用的DDR */
    DUMP_SEC_L2HAC_LLRAM = 6,          /**< L2HAC使用的LLRAM */
    DUMP_SEC_PDE = 7,                  /**< PDE 日志 */
    DUMP_SEC_NRCCPU_LLRAM = 8,         /**< NRCCPU使用LLRAM */
    DUMP_SEC_NRSHARE = 9,              /**< NR的共享内存 */
    DUMP_SEC_LTEVPHY_DUMP = 10,        /**< LTEV PHY的日志 */
    DUMP_SEC_LR_LLRAM = 11,            /**< LR使用的LLRAM */
    DUMP_SEC_TSP_L2MEM_DUMP = 12,      /**< TSP核使用的L2MEM */
    DUMP_SEC_TSP_DSS0_L1MEM_DUMP = 13, /**< TSP DSS0使用的L1MEM */
    DUMP_SEC_TSP_DSS1_L1MEM_DUMP = 14, /**< TSP DSS0使用的L1MEM */
    DUMP_SEC_TSP_DSS2_L1MEM_DUMP = 15, /**< TSP DSS0使用的L1MEM */
    DUMP_SEC_TSP_DSS3_L1MEM_DUMP = 16, /**< TSP DSS0使用的L1MEM */
    DUMP_SEC_TVP_L1MEM_DUMP = 17,      /**< TVP核使用的L1 MEM */
    DUMP_SEC_TVP_L2MEM_DUMP = 18,      /**< TVP使用L2 MEM */
    DUMP_SEC_TVP_DUMP = 19,            /**< TVP的DDR日志 */
    DUMP_SEC_FILE_BUTT,
} dump_sec_file_e;

#define SEC_DUMP_FILE_NAME_LEN 28
#define SEC_DUMP_FILE_LIST_NUM DUMP_SEC_FILE_BUTT

typedef struct {
    unsigned int magic;                     /* magic num  0x5678fedc */
    unsigned int packet_num;                /* BD包个数 */
    unsigned int total_length;              /* 总包长 */
    unsigned int lp_length;                 /* 最后一个包的长度 */
    char file_name[SEC_DUMP_FILE_NAME_LEN]; /* 需要保存的文件名 */
    unsigned int resv;
} dump_ddr_trans_head_info_s;

typedef struct __attribute__((packed, aligned(4))) {
    dump_sec_file_e dumpfile;
    u32 attribute;
    u64 phy_addr;
    u32 save_offset;
    u32 length;
    char name[SEC_DUMP_FILE_NAME_LEN];
    u32 resv; /* 8byte allign */
} dump_sec_file_info_s;

typedef struct __attribute__((packed, aligned(4))) {
    u32 sec_dump_cmd;
    u32 socp_base_addr;
    u64 dump_sec_bd_paddr;
    u32 dump_sec_bd_size;
    u32 dump_sec_header_size;
    u32 dump_sec_bd_woffset;
    u32 socp_dst_channel_id;
    u32 socp_cpsrc_chnl_id;
    u32 socp_nrsrc_chnl_id;
    dump_sec_file_info_s file_list[SEC_DUMP_FILE_LIST_NUM];
} dump_sec_secos_packet_s;

typedef struct {
    u64 data_addr; /**< bd data buffer address */
    u16 data_len;  /**< bd data buffer length */
    u16 data_type; /**< bd data buffer type */
    u32 reservd;   /**< reservd */
} socp_bd_data_s;

typedef struct {
    dump_sec_file_e dumpfile;
    const char *ddr_layout_name;
} dump_sec_ddr_desc_s;

dump_sec_ddr_desc_s g_dump_sec_file[] = {
    { DUMP_SEC_MDM_DDR, "mdm_ddr" },
    { DUMP_SEC_NRCCPU_DDR, "mdm_nr_ddr" },
    { DUMP_SEC_SEC_SHARED, "share_sec_ddr" }, /* 5010及以后 */
    { DUMP_SEC_SEC_SHARED, "sec_share_ddr" }, /* 5000及以前 */
    { DUMP_SEC_TVP_DUMP, "tvp_ddr" }
};

dump_sec_secos_packet_s *g_sec_dump_secos_packet = NULL;
void *g_socp_addr = NULL;
u8 *g_dump_sec_bd_vaddr = NULL;
dump_ddr_trans_head_info_s *g_dump_sec_header_vaddr = NULL;
u32 g_current_attr;

static inline bool is_current_plat_match(u32 except_attr)
{
    u32 current_plat = DUMP_ATTR_DECODE_PLAT(g_current_attr);
    u32 except_plat = DUMP_ATTR_DECODE_PLAT(except_attr);
    return DUMP_EXISTS_ATTRIBUTE(except_plat, current_plat);
}

static inline bool is_current_dump_level_match(u32 except_attr)
{
    u32 current_level = DUMP_ATTR_DECODE_DUMP_LEVEL(g_current_attr);
    u32 except_level = DUMP_ATTR_DECODE_DUMP_LEVEL(except_attr);
    return DUMP_EXISTS_ATTRIBUTE(except_level, current_level);
}

static inline bool is_current_feature_match(u32 except_attr)
{
    u32 current_feature = DUMP_ATTR_DECODE_DUMP_LEVEL(g_current_attr);
    u32 except_feature = DUMP_ATTR_DECODE_DUMP_LEVEL(except_attr);
    return DUMP_MATCH_ATTRIBUTE(except_feature, current_feature);
}

static inline bool is_default_file(u32 except_attr)
{
    return (DUMP_ATTR_DECODE_DEFAULT(except_attr) != 0);
}

bool dump_sec_is_file_need_save(dump_sec_file_info_s *sec_file_info)
{
    if (sec_file_info == NULL) {
        return false;
    }
    if (!is_default_file(sec_file_info->attribute)) {
        return false;
    }
    if (!is_current_plat_match(sec_file_info->attribute)) {
        return false;
    }
    if (!is_current_dump_level_match(sec_file_info->attribute)) {
        return false;
    }
    if (!is_current_feature_match(sec_file_info->attribute)) {
        return false;
    }
    return true;
}

u64 dump_socp_virt_to_phy(u8 *vaddr)
{
    return (u64)g_sec_dump_secos_packet->dump_sec_bd_paddr + (uintptr_t)(vaddr - g_dump_sec_bd_vaddr);
}

u32 dump_sec_get_max_file_num(void)
{
    return (g_sec_dump_secos_packet->dump_sec_header_size / sizeof(dump_ddr_trans_head_info_s));
}

int dump_sec_file_info_fill(dump_ddr_trans_head_info_s *trancs_head, u64 addr, unsigned int length)
{
    unsigned int i = 0;
    u64 bd_addr = addr;

    socp_bd_data_s *bd_info = NULL;
    unsigned int bd_num;
    u32 used_size = g_sec_dump_secos_packet->dump_sec_bd_woffset;
    /* 判断当前支持最大的BD包数是否满足限额 */
    bd_num = (g_sec_dump_secos_packet->dump_sec_bd_size - used_size) / sizeof(socp_bd_data_s);
    if ((used_size < g_sec_dump_secos_packet->dump_sec_bd_size) && (bd_num <= trancs_head->packet_num)) {
        sec_dump_print("the avaliable bd buffer is not enough for bdinfo fill!\n");
        return -1;
    }

    bd_info = (socp_bd_data_s *)(g_dump_sec_bd_vaddr + used_size);
    bd_info->data_addr = dump_socp_virt_to_phy((u8 *)trancs_head);
    bd_info->data_len = sizeof(dump_ddr_trans_head_info_s);
    bd_info->data_type = 0;
    bd_info->reservd = 0;

    for (i = 1; i < (trancs_head->packet_num + 1); i++) {
        (bd_info + i)->data_addr = bd_addr;
        (bd_info + i)->data_len = (u16)((length > DUMP_SEC_TRANS_SIGNLE_MAX_SIZE) ? DUMP_SEC_TRANS_SIGNLE_MAX_SIZE
                                                                                    : length);
        (bd_info + i)->data_type = 0;
        (bd_info + i)->reservd = 0;
        bd_addr = bd_addr + (bd_info + i)->data_len;
        length = length - (bd_info + i)->data_len;
        if (length == 0) {
            break;
        }
    }
    g_sec_dump_secos_packet->dump_sec_bd_woffset += sizeof(socp_bd_data_s) * (trancs_head->packet_num + 1);

    trancs_head->magic = DUMP_SEC_TRANS_FILE_MAGIC;

    return 0;
}

int dump_sec_file_trans(dump_sec_file_info_s *file_info)
{
    u32 i = 0;
    dump_ddr_trans_head_info_s *trancs_head = NULL;
    u32 ret;

    /* 查询空余头节点BD包空间 */
    for (i = 0; i < dump_sec_get_max_file_num(); i++) {
        trancs_head = g_dump_sec_header_vaddr + i;
        if (trancs_head->magic != DUMP_SEC_TRANS_FILE_MAGIC) {
            break;
        }
    }

    if (i == dump_sec_get_max_file_num()) {
        return -1;
    }

    trancs_head->lp_length = file_info->length % DUMP_SEC_TRANS_SIGNLE_MAX_SIZE;
    trancs_head->packet_num = file_info->length / DUMP_SEC_TRANS_SIGNLE_MAX_SIZE;
    trancs_head->packet_num = (trancs_head->lp_length) ? (trancs_head->packet_num + 1) : (trancs_head->packet_num);
    trancs_head->total_length = file_info->length;
    ret = (u32)strncpy_s(trancs_head->file_name, sizeof(trancs_head->file_name), file_info->name,
                         strlen(file_info->name)); /*lint !e421*/
    if (ret != 0) {
        return ret;
    }

    if (dump_sec_file_info_fill(trancs_head, file_info->phy_addr, file_info->length)) {
        return -1;
    }

    return 0;
}

int sec_dump_get_file_info(dump_sec_file_info_s *file_info)
{
    u32 i;
    unsigned long phy_addr;
    unsigned int size = 0;
    for (i = 0; i < sizeof(g_dump_sec_file) / sizeof(dump_sec_ddr_desc_s); i++) {
        if (file_info->dumpfile != g_dump_sec_file[i].dumpfile) {
            continue;
        }
        phy_addr = mdrv_mem_region_get(g_dump_sec_file[i].ddr_layout_name, &size);
        if (phy_addr == 0) {
            continue;
        }
        file_info->phy_addr = phy_addr;
        file_info->length = size;
        if (size > file_info->save_offset) {
            file_info->phy_addr += file_info->save_offset;
            file_info->length -= file_info->save_offset;
        } else {
            sec_dump_print("save_offset invalid.\n");
            file_info->save_offset = 0;
        }
        return 0;
    }
    return -1;
}


void socp_cfg_src_chnl(void)
{
    u32 chnl = g_sec_dump_secos_packet->socp_cpsrc_chnl_id;
    writel(SEC_DUMP_ADDRL(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFADDR_L(chnl)));
    writel(SEC_DUMP_ADDRH(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFADDR_H(chnl)));
    writel(SEC_DUMP_ADDRL(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQADDR_L(chnl)));
    writel(SEC_DUMP_ADDRH(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQADDR_H(chnl)));
    writel(0, (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQCFG(chnl)));
    writel(g_sec_dump_secos_packet->dump_sec_bd_woffset,
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFWPTR(chnl)));
    writel(0, (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFRPTR(chnl)));
    writel(g_sec_dump_secos_packet->dump_sec_bd_size,
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFDEPTH(chnl)));
    writel(SOCP_SRC_CFG_DEFAULT(g_sec_dump_secos_packet->socp_dst_channel_id),
           (void *)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFCFG(chnl)));
}

void socp_src_channel_enable(u32 channel_id)
{
    volatile unsigned int src_cfg;
    unsigned int rp;
    unsigned int wp;
    if (channel_id == 0) {
        return;
    }

    rp = readl((unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFRPTR(channel_id)));
    wp = readl((unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFWPTR(channel_id)));
    if (rp == wp) {
        sec_dump_print("rp == wp");
        return;
    }

    src_cfg = readl((volatile unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFCFG(channel_id)));
    if (src_cfg & 0x1) {
        return;
    }
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQWPTR(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQRPTR(channel_id)));

    src_cfg |= 0x1;
    writel(src_cfg, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFCFG(channel_id)));

    return;
}

void socp_src_channel_disable(u32 channel_id)
{
    volatile unsigned int src_cfg;

    if (channel_id == 0) {
        return;
    }

    src_cfg = readl((unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFCFG(channel_id)));
    if (src_cfg & 0x1) {
        src_cfg = src_cfg & (~1);
        writel(src_cfg, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFCFG(channel_id)));
    }
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFRPTR(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_BUFWPTR(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQWPTR(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + SOCP_REG_ENCSRC_RDQRPTR(channel_id)));

    return;
}

int socp_trans_files(void)
{
    u32 i;
    int ret = 0;
    dump_sec_file_info_s *file_info = g_sec_dump_secos_packet->file_list;
    paddr_t bd_paddr = g_sec_dump_secos_packet->dump_sec_bd_paddr;
    u32 buf_size = g_sec_dump_secos_packet->dump_sec_bd_size + g_sec_dump_secos_packet->dump_sec_header_size;
    if (bd_paddr == 0 || buf_size == 0 || g_sec_dump_secos_packet->socp_cpsrc_chnl_id == 0) {
        return -1;
    }
    if (sre_mmap(bd_paddr, buf_size, (unsigned int *)&g_dump_sec_bd_vaddr, non_secure, non_cache)) {
        g_dump_sec_bd_vaddr = NULL;
        return -1;
    }
    g_dump_sec_header_vaddr =
        (dump_ddr_trans_head_info_s *)((uintptr_t)g_dump_sec_bd_vaddr + g_sec_dump_secos_packet->dump_sec_bd_size);
    g_sec_dump_secos_packet->dump_sec_bd_woffset = 0;
    (void)memset_s(g_dump_sec_bd_vaddr, g_sec_dump_secos_packet->dump_sec_bd_size, 0,
                   g_sec_dump_secos_packet->dump_sec_bd_size);

    for (i = 0; (i < SEC_DUMP_FILE_LIST_NUM) && file_info->name[0]; i++, file_info++) {
        ret = sec_dump_get_file_info(file_info);
        if (ret != 0) {
            continue;
        }
        if (!dump_sec_is_file_need_save(file_info)) {
            continue;
        }
        ret = dump_sec_file_trans(file_info);
        if (ret != 0) {
            goto error;
        }
    }
    if (g_sec_dump_secos_packet->dump_sec_bd_woffset == 0) {
        goto error;
    }
    v7_dma_flush_range(g_dump_sec_bd_vaddr, g_dump_sec_bd_vaddr + buf_size);
    socp_cfg_src_chnl();
    return 0;
error:
    (void)sre_unmap(g_dump_sec_bd_vaddr, buf_size);
    socp_src_channel_disable(g_sec_dump_secos_packet->socp_cpsrc_chnl_id);
    g_dump_sec_bd_vaddr = NULL;
    g_dump_sec_header_vaddr = NULL;
    return -1;
}

int sec_dump_basecfg_init(unsigned int arg1)
{
    int ret;
    int prot = PROT_READ | PROT_WRITE | PROT_nGnRnE | PROT_MA_NC;
    paddr_t phy_addr;

    if (arg1 == 0) {
        sec_dump_print("param invalid\n");
        return -1;
    }
    phy_addr = arg1;

    if (sre_mmap((paddr_t)phy_addr, sizeof(dump_sec_secos_packet_s), (unsigned int *)&g_sec_dump_secos_packet,
                 non_secure, non_cache)) {
        sec_dump_print("page map failed[0x%llx]", (u64)phy_addr);
        g_sec_dump_secos_packet = NULL;
        return -1;
    }
    g_socp_addr = hm_mmap_physical(NULL, SOCP_REG_SIZE, prot, g_sec_dump_secos_packet->socp_base_addr);
    if (g_socp_addr == NULL || g_socp_addr == MAP_FAILED) {
        sec_dump_print("socp_reg_addr map failed[0x%llx]", (u64)g_sec_dump_secos_packet->socp_base_addr);
        sre_unmap(g_sec_dump_secos_packet, sizeof(dump_sec_secos_packet_s));
        return -1;
    }
    return 0;
}

void sec_dump_basecfg_exit(void)
{
    (void)sre_unmap(g_sec_dump_secos_packet, sizeof(dump_sec_secos_packet_s));
    (void)hm_munmap(g_socp_addr, SOCP_REG_SIZE);
    g_sec_dump_secos_packet = NULL;
    g_socp_addr = NULL;
}

int bsp_sec_dump_save_log(unsigned int arg1, void *arg2, unsigned int arg3)
{
    int ret = 0;
    UNUSED(arg2);
    UNUSED(arg3);

    if (sec_dump_basecfg_init(arg1)) {
        return -1;
    }

    switch (g_sec_dump_secos_packet->sec_dump_cmd) {
        case MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD:
            /* enable src channel */
            socp_src_channel_enable(g_sec_dump_secos_packet->socp_cpsrc_chnl_id);
            sec_dump_print("enable sec dump\n");
            break;

        case MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD:
            /* disable src channel */
            socp_src_channel_disable(g_sec_dump_secos_packet->socp_cpsrc_chnl_id);
            sec_dump_print("disable sec dump\n");
            break;
        case MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD:
            /* enable src channel */
            socp_src_channel_enable(g_sec_dump_secos_packet->socp_nrsrc_chnl_id);
            sec_dump_print("enable sec dump\n");
            break;

        case MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD:
            /* disable src channel */
            socp_src_channel_disable(g_sec_dump_secos_packet->socp_nrsrc_chnl_id);
            sec_dump_print("disable sec dump\n");
            break;
        case MODEM_SEC_DUMP_RETRANS_LOG_CMD:
            ret = socp_trans_files();
            sec_dump_print("retrans sec_dump\n");
            break;

        default:
            socp_src_channel_disable(g_sec_dump_secos_packet->socp_cpsrc_chnl_id);
            socp_src_channel_disable(g_sec_dump_secos_packet->socp_nrsrc_chnl_id);

            break;
    }

    sec_dump_basecfg_exit();
    return ret;
}

void dump_sec_plat_init(void)
{
#ifdef CONFIG_MODEM_FULL_DUMP
    g_current_attr |= DUMP_ATTR_SAVE_FULLDUMP;
#endif

#ifdef CONFIG_MODEM_MINI_DUMP
    g_current_attr |= DUMP_ATTR_SAVE_MINIDUMP;
#endif

#ifdef CONFIG_BALONG_EXTRA_RDR
    g_current_attr |= DUMP_ATTR_SAVE_EXTRA_MDM;
#endif

#ifdef BSP_CONFIG_PHONE_TYPE
    g_current_attr |= DUMP_ATTR_SAVE_PHONE;
#else
    g_current_attr |= DUMP_ATTR_SAVE_MBB;
#endif

#ifdef FEATURE_DRV_LTEV
    g_current_attr |= DUMP_ATTR_SAVE_FEATURE_LTEV;
#endif
}

int bsp_sec_dump_init(void)
{
    dump_sec_plat_init();
    (void)bsp_modem_call_register(FUNC_SEC_DUMP_CHANNEL_ENABLE, (MODEM_CALL_HOOK_FUNC)bsp_sec_dump_save_log);
    sec_dump_print("g_current_attr 0x%x\n", g_current_attr);
    return 0;
}

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(sec_dump, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_sec_dump_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
