/*
 * History:
 * 2018-12-10 create this file
 */
#ifndef __TZMP2_OPS_H__
#define __TZMP2_OPS_H__

#include <sec_region_ops.h>

/****************************************************************************/
/*                                                                          */
/*          macros , constants,  module-wide global variables               */
/*                                                                          */
/****************************************************************************/
#define EN_CA_RD  (1)
#define DIS_CA_RD (0)

extern int tzmp2_init(void);
extern int tzmp2_set_sec(u64 phys, u32 size);
extern int tzmp2_unset_sec(u64 phys, u32 size);
extern int tzmp2_check_sec(u64 phys, u32 size);
#ifdef CONFIG_HISI_DDR_CA_RD
extern s32 ddrc_ca_rd_cfg(s32 ca_rd_enable);
#else
inline static s32 ddrc_ca_rd_cfg(s32 ca_rd_enable)
{
	(void)ca_rd_enable;
	return 0;
}
#endif

#if defined(DDR_CA_RD_PRINT) && defined(CONFIG_HISI_DDR_CA_RD)
void ddrc_ca_rd_info_dump(void);
#else
inline static void ddrc_ca_rd_info_dump(void)
{
	return;
}
#endif

extern int tzmp2_pro_cfg(struct sglist *sglist, enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type);

#endif // __TZMP2_OPS_H__