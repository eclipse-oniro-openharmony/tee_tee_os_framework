/*
 * ISP driver, hisp.h
 */


#ifndef _HISI_ISP_H_
#define _HISI_ISP_H_
#include "dynion.h"

#ifdef CONFIG_HISI_ISP_SEC_IMAGE
extern int hisi_isp_reset(void);
extern int hisi_isp_disreset(unsigned int remapddr);
unsigned int get_isp_cma_size(void);
unsigned int get_isp_img_size(void);
unsigned int get_isp_baseaddr(void);
#else
static inline unsigned int get_isp_cma_size(void){return 0;}
static inline unsigned int get_isp_img_size(void){return 0;}
static inline unsigned int get_isp_baseaddr(void){return 0;}
static inline int hisi_isp_reset(void){return 0;}
static inline int hisi_isp_disreset(__attribute__((unused)) unsigned int remapddr){return 0;}
#endif
int __attribute__((weak)) is_isp_rdr_addr(__attribute__((unused)) struct sglist *sgl){ return 0;}
#endif /* _HISI_ISP_H_ */

