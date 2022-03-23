#ifndef HISEE_VIDEO_SMMU_H
#define HISEE_VIDEO_SMMU_H

#include <pal_types.h>

err_bsp_t hisee_video_smmu_init(u32 buffer_id, u32 size, u32 *iova);
void hisee_video_smmu_deinit(u32 buffer_id, u32 size);

#endif
