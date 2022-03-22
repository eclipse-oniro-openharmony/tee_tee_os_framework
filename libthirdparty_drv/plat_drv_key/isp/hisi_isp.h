/*
 * hisilicon ISP driver, hisp.h
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#ifndef _HISI_ISP_H_
#define _HISI_ISP_H_
#include "dynion.h"

#ifdef CONFIG_PRODUCT_ARMPC
static inline unsigned int get_isp_cma_size(void){return 0;}
static inline unsigned int get_isp_img_size(void){return 0;}
static inline unsigned int get_isp_baseaddr(void){return 0;}
static inline int hisi_isp_reset(void){return 0;}
static inline int hisi_isp_disreset(unsigned int remapddr){
    (void)remapddr;
    return 0;
}
#else
extern int hisi_isp_reset(void);
extern int hisi_isp_disreset(unsigned int remapddr);
unsigned int get_isp_cma_size(void);
unsigned int get_isp_img_size(void);
unsigned int get_isp_baseaddr(void);
#endif
int is_isprdr_addr(struct sglist *sgl);

#endif /* _HISI_ISP_H_ */

