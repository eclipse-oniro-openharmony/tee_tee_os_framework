/*
 * History:
 * 2017-03-14 create this file
 */
#ifndef __SEC_REGION_OPS_H__
#define __SEC_REGION_OPS_H__

#include "dynion.h" // struct sglist
#include "mem_page_ops.h"

/****************************************************************************/
/*                                                                          */
/*          macros , constants,  module-wide global variables               */
/*                                                                          */
/****************************************************************************/

/* sec_feature same as fastboot */
enum SEC_FEATURE
{
/* sub region feature */
	DDR_SEC_TINY = 1,
	DDR_SEC_TUI = 2,
	DDR_SEC_EID = 5,

/* mixed feature */
	DDR_SEC_FACE = 0x10, /* include 2D_FACE, 3D_FACE_ISP(64M), 3D_FACE_CAMERA(108M), 3D_FACE_ALGO(NORMAL_RGN) */

/* normal region feature */
	DDR_SEC_PGTABLE = 0x20,
	DDR_SEC_HIFI_RESET = 0x21,

/* mpu protect */
	DDR_DRM_PRO = 0x40,

/* to be deleted */
	DDR_SEC_SION,
	DDR_SEC_MAX,
};

typedef enum
{
	DDR_SET_SEC,
	DDR_UNSET_SEC,
	DDR_CHECK_SEC,
	DDR_CHECK_UNSEC, /* use internally */
} DDR_CFG_TYPE;

/*
* sglist:保存segment数组的首地址和数组长度;
* featue_id:安全业务的id值;
* ddr_cfg_type:DDR_SET_SEC表示配置安全, DDR_UNSET_SEC表示解除安全配置,
* 配置成功返回0, 失败返回-1;
* DDR_CHECK_SEC检查内存地址的安全属性, 安全返回0, 校验失败返回-1;
*/
#ifdef CONFIG_SOC_WE_WORKAROUND
extern int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
extern int __ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
#else
extern int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
#endif
/*
* sglist:保存segment数组的首地址和数组长度;
* pid:业务TA的pid;
* 校验成功返回0, 失败返回-1;
*/
extern int check_sglist_pid(struct sglist *sglist, int feature_id);
/*
* sglist:保存segment数组的首地址和数组长度;
* 不允许sglist含有安全地址;
* 校验成功返回0, 失败返回-1;
*/
extern int check_unsec_sglist(struct sglist *sglist);

/* return 1 is secure return 0 is unsecure */
extern unsigned int is_sec_addr(u64 start_addr, u64 end_addr);
extern int mddrc_sec_cfg(u64 start_addr, u64 end_addr);
extern int mddrc_sec_clean(u64 start_addr, u64 end_addr);
extern int ddr_sec_cfg_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id);
#ifdef CONFIG_SOC_WE_WORKAROUND
extern int ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id);
extern int __ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id);
#else
extern int ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id);
#endif
extern int ddr_sec_check_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id);
extern int sec_region_init(void);

#endif // __SEC_REGION_OPS_H__
