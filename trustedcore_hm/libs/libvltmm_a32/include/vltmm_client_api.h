/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020.. All rights reserved.
 * Description: vltmm client api.
 * Create: 2020-03-16
 * Notes:
 * History: 2020-03-16 create
 */

#ifndef __VLTMM_CLIENT_API_H_
#define __VLTMM_CLIENT_API_H_

enum SEC_SVC {
	SEC_TUI = 0,
	SEC_EID,
	SEC_TINY,
	SEC_FACE_ID,
	SEC_FACE_ID_3D,
	SEC_DRM_TEE,
	SEC_HIAI,
	SEC_IVP,
	SEC_ISP,
	SEC_SVC_MAX,
};

extern void vlt_create_zone(uint32_t sid, uint32_t maxsize, uint32_t align);
extern void vlt_destroy_zone(uint32_t sid);
extern void *vlt_malloc(uint32_t size);
extern void vlt_free(void *ptr, uint32_t size);

/* siommu domain api */
extern int vlt_create_siommu_domain(uint32_t sid, uint32_t size);
extern int vlt_destroy_siommu_domain(uint32_t sid);

extern uint32_t vlt_open(uint32_t size);
extern void vlt_close(uint32_t fd);
extern void *vlt_map(uint32_t fd, uint32_t cached);
extern int vlt_unmap(uint32_t fd, void *va);
extern int vlt_import_fd(uint32_t fd);
extern int vlt_errno(void);

#endif
