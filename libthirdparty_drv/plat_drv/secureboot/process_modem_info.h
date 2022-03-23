/*
 * hisilicon MODEM process, process_modem_info.h
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 */

#ifndef _PROCESS_MODEM_INFO_H_
#define _PROCESS_MODEM_INFO_H_

#include <sre_typedef.h>

#define DYNAMIC_LOAD_IMG (0x5A5AC003)
#define NON_DYNAMIC_LOAD_IMG (0x5A5AC004)
#define MODEM_SYS_IMG (0x5A5AC001)
#define NON_MODEM_SYS_IMG (0x5A5AC002)
#define NEED_VERIFY_FLAG (1U)

#define CORE_ID_MAX 2
enum CMD_TYPE {
    VERIFY_IMAGE = 0,
    VERIFY_PATCH_IMAGE = 1,
    SPLICING_IMAGE = 2,
    INFLATE_IMAGE = 3,
};

struct secboot_splicing_info_s {
    UINT32 image_addr;
    UINT32 image_size;
    UINT32 splicing_addr;
    UINT32 splicing_size;
    UINT32 patch_addr;
    UINT32 patch_size;
};

UINT32 secboot_is_dynamic_load(UINT32 soc_type);
UINT32 secboot_config_dynamic_load_addr(UINT32 soc_type);
UINT32 secboot_config_dynamic_load_addr(UINT32 soc_type);
UINT32 secboot_clean_dynamic_load_flag(UINT32 soc_type);
UINT32 hisi_modem_inflate(UINT32 SoC_Type, UINT32 Inflate_Img_Offset);
UINT32 hisi_modem_disreset(UINT32 soc_type);
UINT32 hisi_secboot_splicing_modem_img(UINT32 SoC_Type, struct secboot_splicing_info_s *splicing_info);
UINT32 hisi_secboot_get_aslr_offset(UINT32 SoC_Type);
void hisi_secboot_copy_code_for_aslr(UINT32 SoC_Type, struct secboot_splicing_info_s *virt_splicing_info);

#endif
