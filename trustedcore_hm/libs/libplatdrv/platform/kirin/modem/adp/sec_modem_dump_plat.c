/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include <product_config.h>
#include <osl_balong.h>
#include <mem_page_ops.h>
#include <drv_module.h>
#include <drv_mem.h>
#include <mem_ops.h>
#include <hm_mman_ext.h>
#include <tee_log.h> /* uart_printf_func */
#include <bsp_modem_call.h>
#include <securec.h>
#include <secboot.h>

#define SOCP_REG_ENCSRC_OFFSET 0x300
#define SOCP_REG_SIZE 0x2000

#define socp_reg_encsrc_bufwptr(m) (SOCP_REG_ENCSRC_OFFSET + 0x00 + (m)*0x40)
#define socp_reg_encsrc_bufrptr(m) (SOCP_REG_ENCSRC_OFFSET + 0x04 + (m)*0x40)
#define socp_reg_encsrc_bufaddr_l(m) (SOCP_REG_ENCSRC_OFFSET + 0x08 + (m)*0x40)
#define socp_reg_encsrc_bufaddr_h(m) (SOCP_REG_ENCSRC_OFFSET + 0x0C + (m)*0x40)
#define socp_reg_encsrc_bufdepth(m) (SOCP_REG_ENCSRC_OFFSET + 0x10 + (m)*0x40)
#define socp_reg_encsrc_bufcfg(m) (SOCP_REG_ENCSRC_OFFSET + 0x14 + (m)*0x40)
#define socp_reg_encsrc_rdqwptr(m) (SOCP_REG_ENCSRC_OFFSET + 0x18 + (m)*0x40)
#define socp_reg_encsrc_rdqrptr(m) (SOCP_REG_ENCSRC_OFFSET + 0x1C + (m)*0x40)
#define socp_reg_encsrc_rdqaddr_l(m) (SOCP_REG_ENCSRC_OFFSET + 0x20 + (m)*0x40)
#define socp_reg_encsrc_rdqaddr_h(m) (SOCP_REG_ENCSRC_OFFSET + 0x24 + (m)*0x40)
#define socp_reg_encsrc_rdqcfg(m) (SOCP_REG_ENCSRC_OFFSET + 0x28 + (m)*0x40)

#define MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD 0x56781234
#define MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD 0x78563412
#define MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD 0x12345678
#define MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD 0x34127856
#define MODEM_SEC_DUMP_RETRANS_LOG_CMD 0xDEF09ABC

#define DUMP_SEC_TRANS_SIGNLE_MAX_SIZE 0xFFF0
#define DUMP_SEC_TRANS_FILE_MAGIC 0x5678FEDC

#define sec_dump_addrl(addr) ((u64)(addr)&0xFFFFFFFF)
#define sec_dump_addrh(addr) (((u64)(addr) >> 32) & 0xFFFFFFFF)
#define socp_src_cfg_default(dst_chnl) (0x00000e04 | (((dst_chnl)&0x3) << 4))

#define bit(n) (1 << (n))

#define DUMP_ATTR_SAVE_DEFAULT bit(0)
#define DUMP_ATTR_SAVE_EXTRA_MDM bit(1)
#define DUMP_ATTR_SAVE_MBB bit(2)
#define DUMP_ATTR_SAVE_PHONE bit(3)
#define DUMP_ATTR_SAVE_MINIDUMP bit(4)
#define DUMP_ATTR_SAVE_FULLDUMP bit(5)
#define DUMP_ATTR_SAVE_FEATURE_LTEV bit(6)

#define dump_attr_decode_default(attr) ((attr)&DUMP_ATTR_SAVE_DEFAULT)
#define dump_attr_decode_plat(attr) ((attr) & (DUMP_ATTR_SAVE_EXTRA_MDM | DUMP_ATTR_SAVE_MBB | DUMP_ATTR_SAVE_PHONE))
#define dump_attr_decode_dump_level(attr) ((attr) & (DUMP_ATTR_SAVE_MINIDUMP | DUMP_ATTR_SAVE_FULLDUMP))
#define dump_attr_decode_feature(attr) ((attr)&DUMP_ATTR_SAVE_FEATURE_LTEV)

#define dump_match_attribute(except_attr, curr_attr) (((except_attr) & (curr_attr)) == (except_attr))
#define dump_exists_attribute(except_attr, curr_attr) (((except_attr) & (curr_attr)) != 0)
#define sec_dump_print(fmt, ...) uart_printf_func("[sec_dump]:" fmt, ##__VA_ARGS__)

typedef enum {
    DUMP_SEC_MDM_DDR = 0,
    DUMP_SEC_SEC_SHARED = 1,
    DUMP_SEC_LPHY_DUMP = 2,
    DUMP_SEC_NRPHY_DUMP = 3,
    DUMP_SEC_EASYRF_DUMP = 4,
    DUMP_SEC_NRCCPU_DDR = 5,
    DUMP_SEC_L2HAC_LLRAM = 6,
    DUMP_SEC_PDE = 7,
    DUMP_SEC_NRCCPU_LLRAM = 8,
    DUMP_SEC_NRSHARE = 9,
    DUMP_SEC_LTEVPHY_DUMP = 10,
    DUMP_SEC_LR_LLRAM = 11,
    DUMP_SEC_TSP_L2MEM_DUMP = 12,
    DUMP_SEC_TSP_DSS0_L1MEM_DUMP = 13,
    DUMP_SEC_TSP_DSS1_L1MEM_DUMP = 14,
    DUMP_SEC_TSP_DSS2_L1MEM_DUMP = 15,
    DUMP_SEC_TSP_DSS3_L1MEM_DUMP = 16,
    DUMP_SEC_TVP_L1MEM_DUMP = 17,
    DUMP_SEC_TVP_L2MEM_DUMP = 18,
    DUMP_SEC_TVP_DUMP = 19,
    DUMP_SEC_FILE_BUTT,
} dump_sec_file_e;

#define SEC_DUMP_FILE_NAME_LEN 28
#define SEC_DUMP_FILE_LIST_NUM DUMP_SEC_FILE_BUTT

typedef struct {
    unsigned int magic;                     /* magic num  0x5678fedc */
    unsigned int packet_num;                /* bd pkt bum */
    unsigned int total_length;
    unsigned int lp_length;                 /* last pkt length*/
    char file_name[SEC_DUMP_FILE_NAME_LEN];
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
    u64 data_addr; /* *< bd data buffer address */
    u16 data_len;  /* *< bd data buffer length */
    u16 data_type; /* *< bd data buffer type */
    u32 reservd;   /* *< reservd */
} socp_bd_data_s;

dump_sec_file_info_s g_dump_sec_file[] = {
#ifdef DDR_MCORE_ADDR
    { .dumpfile = DUMP_SEC_MDM_DDR,
      .phy_addr = DDR_MCORE_ADDR,
      .length = DDR_MCORE_SIZE },
#endif
#ifdef DDR_MCORE_NR_ADDR
    { .dumpfile = DUMP_SEC_NRCCPU_DDR,
      .phy_addr = DDR_MCORE_NR_ADDR,
      .length = DDR_MCORE_NR_SIZE },
#endif
#ifdef DDR_SHARED_SEC_ADDR
    { .dumpfile = DUMP_SEC_SEC_SHARED,
      .phy_addr = DDR_SHARED_SEC_ADDR,
      .length = DDR_SHARED_SEC_SIZE },
#endif
#ifdef DDR_SEC_SHARED_ADDR
    { .dumpfile = DUMP_SEC_SEC_SHARED,
      .phy_addr = DDR_SEC_SHARED_ADDR,
      .length = DDR_SEC_SHARED_SIZE },
#endif
#ifdef DDR_SDR_ADDR
    { .dumpfile = DUMP_SEC_TVP_DUMP,
      .phy_addr = DDR_SDR_ADDR,
      .length = DDR_SDR_SIZE },
#endif
    { .dumpfile = DUMP_SEC_FILE_BUTT }
};

dump_sec_secos_packet_s *g_sec_dump_secos_packet = NULL;
void *g_socp_addr = NULL;
u8 *g_dump_sec_bd_vaddr = NULL;
dump_ddr_trans_head_info_s *g_dump_sec_header_vaddr = NULL;
u32 g_current_attr;

static inline bool is_current_plat_match(u32 except_attr)
{
    u32 current_plat = dump_attr_decode_plat(g_current_attr);
    u32 except_plat = dump_attr_decode_plat(except_attr);
    return dump_exists_attribute(except_plat, current_plat);
}

static inline bool is_current_dump_level_match(u32 except_attr)
{
    u32 current_level = dump_attr_decode_dump_level(g_current_attr);
    u32 except_level = dump_attr_decode_dump_level(except_attr);
    return dump_exists_attribute(except_level, current_level);
}

static inline bool is_current_feature_match(u32 except_attr)
{
    u32 current_feature = dump_attr_decode_dump_level(g_current_attr);
    u32 except_feature = dump_attr_decode_dump_level(except_attr);
    return dump_match_attribute(except_feature, current_feature);
}

static inline bool is_default_file(u32 except_attr)
{
    return (dump_attr_decode_default(except_attr) != 0);
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
    unsigned int i;
    u64 bd_addr = addr;

    socp_bd_data_s *bd_info = NULL;
    unsigned int bd_num;
    u32 used_size = g_sec_dump_secos_packet->dump_sec_bd_woffset;
    /* check if bd buffer enough */
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

int dump_sec_file_trans(const dump_sec_file_info_s *file_info)
{
    u32 i;
    dump_ddr_trans_head_info_s *trancs_head = NULL;
    u32 ret;

    /* check if header buffer enough */
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
    for (i = 0; i < sizeof(g_dump_sec_file) / sizeof(dump_sec_file_info_s); i++) {
        if (file_info->dumpfile != g_dump_sec_file[i].dumpfile) {
            continue;
        }
        file_info->phy_addr = g_dump_sec_file[i].phy_addr;
        file_info->length = g_dump_sec_file[i].length;
        if (g_dump_sec_file[i].length > file_info->save_offset) {
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
    writel(sec_dump_addrl(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufaddr_l(chnl)));
    writel(sec_dump_addrh(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufaddr_h(chnl)));
    writel(sec_dump_addrl(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqaddr_l(chnl)));
    writel(sec_dump_addrh(g_sec_dump_secos_packet->dump_sec_bd_paddr),
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqaddr_h(chnl)));
    writel(0, (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqcfg(chnl)));
    writel(g_sec_dump_secos_packet->dump_sec_bd_woffset,
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufwptr(chnl)));
    writel(0, (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufrptr(chnl)));
    writel(g_sec_dump_secos_packet->dump_sec_bd_size,
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufdepth(chnl)));
    writel(socp_src_cfg_default(g_sec_dump_secos_packet->socp_dst_channel_id),
           (void *)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufcfg(chnl)));
}

void socp_src_channel_enable(u32 channel_id)
{
    volatile unsigned int src_cfg = 0;
    unsigned int rp = 0;
    unsigned int wp = 0;
    if (channel_id == 0) {
        return;
    }

    rp = readl((unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufrptr(channel_id)));
    wp = readl((unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufwptr(channel_id)));

    if (rp == wp) {
        return;
    }

    src_cfg = readl((volatile unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufcfg(channel_id)));

    if (src_cfg & 0x1) {
        return;
    }

    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqwptr(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqrptr(channel_id)));

    src_cfg |= 0x1;
    writel(src_cfg, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufcfg(channel_id)));

    sec_dump_print("%s 0x%x src_cfg=0x%x\n", __func__, g_socp_addr, src_cfg);
    return;
}

void socp_src_channel_disable(u32 channel_id)
{
    volatile unsigned int src_cfg = 0;

    if (channel_id == 0) {
        return;
    }

    src_cfg = readl((unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufcfg(channel_id)));
    if (src_cfg & 0x1) {
        src_cfg = src_cfg & (~1);
        writel(src_cfg, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufcfg(channel_id)));
    }
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufrptr(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_bufwptr(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqwptr(channel_id)));
    writel(0, (unsigned long)((uintptr_t)g_socp_addr + socp_reg_encsrc_rdqrptr(channel_id)));
    return;
}

int socp_trans_files(void)
{
    u32 i;
    int ret;
    dump_sec_file_info_s *file_info = g_sec_dump_secos_packet->file_list;
    paddr_t bd_paddr = g_sec_dump_secos_packet->dump_sec_bd_paddr;
    u32 buf_size = g_sec_dump_secos_packet->dump_sec_bd_size + g_sec_dump_secos_packet->dump_sec_header_size;
    if (bd_paddr == 0 || buf_size == 0 || g_sec_dump_secos_packet->socp_cpsrc_chnl_id == 0) {
        return -1;
    }
    if (sre_mmap(bd_paddr, buf_size, (unsigned int *)&g_dump_sec_bd_vaddr, non_secure, non_cache)) {
        sec_dump_print("page map failed[0x%lx]", (unsigned long)(uintptr_t)bd_paddr);
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

    if (arg1 == 0) {
        sec_dump_print("FUNC_SEC_DUMP_CHANNEL_ENABLE param invalid\n");
        return -1;
    }

    if (sre_mmap((paddr_t)(uintptr_t)arg1, sizeof(dump_sec_secos_packet_s), (unsigned int *)&g_sec_dump_secos_packet,
                 non_secure, non_cache)) {
        sec_dump_print("page map failed[0x%lx]", (unsigned long)(uintptr_t)arg1);
        g_sec_dump_secos_packet = NULL;
        return -1;
    }
    g_socp_addr = hm_mmap_physical(NULL, SOCP_REG_SIZE, prot, g_sec_dump_secos_packet->socp_base_addr);
    if (g_socp_addr == NULL || g_socp_addr == MAP_FAILED) {
        sec_dump_print("socp_reg_addr map failed[0x%lx]", (unsigned long)g_sec_dump_secos_packet->socp_base_addr);
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

int sec_dump_check_valid_param(u32 arg1)
{
    if (arg1 == MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD || arg1 == MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD ||
        arg1 == MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD || arg1 == MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD ||
        arg1 == MODEM_SEC_DUMP_RETRANS_LOG_CMD) {
        return -1;
    }
    return 0;
}

int bsp_sec_dump_save_log(unsigned int arg1, void *arg2, unsigned int arg3)
{
    int ret = 0;
    UNUSED(arg2);
    UNUSED(arg3);
    if (sec_dump_check_valid_param(arg1)) {
        return -1;
    }
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
