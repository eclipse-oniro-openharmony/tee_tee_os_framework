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
* sglist:����segment������׵�ַ�����鳤��;
* featue_id:��ȫҵ���idֵ;
* ddr_cfg_type:DDR_SET_SEC��ʾ���ð�ȫ, DDR_UNSET_SEC��ʾ�����ȫ����,
* ���óɹ�����0, ʧ�ܷ���-1;
* DDR_CHECK_SEC����ڴ��ַ�İ�ȫ����, ��ȫ����0, У��ʧ�ܷ���-1;
*/
#ifdef CONFIG_SOC_WE_WORKAROUND
extern int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
extern int __ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
#else
extern int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
#endif
/*
* sglist:����segment������׵�ַ�����鳤��;
* pid:ҵ��TA��pid;
* У��ɹ�����0, ʧ�ܷ���-1;
*/
extern int check_sglist_pid(struct sglist *sglist, int feature_id);
/*
* sglist:����segment������׵�ַ�����鳤��;
* ������sglist���а�ȫ��ַ;
* У��ɹ�����0, ʧ�ܷ���-1;
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
