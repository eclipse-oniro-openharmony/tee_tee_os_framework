#include "tee_common.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include <sre_syscalls_ext.h>
#include <stdint.h>
#include <hm_msg_type.h>
#include <sre_syscalls_id_ext.h>

signed int tee_vdec_drv_init();
signed int tee_vdec_drv_exit(int ext_type);
signed int tee_vdec_drv_scd_start(void *stm_cfg, int cfg_size, void *scd_state_reg, int reg_size);
signed int tee_vdec_drv_iommu_map(void *mem_param, void *out_mem_param);
signed int tee_vdec_drv_iommu_unmap(void *mem_param);
signed int tee_vdec_drv_get_active_reg(void *dev_cfg, int cfg_size);
signed int tee_vdec_drv_dec_start(void *dev_cfg, int cfg_size);
signed int tee_vdec_drv_irq_query(void *dev_cfg, int cfg_size, void *read_backup, int backup_size);
signed int tee_vdec_drv_set_dev_reg(int dev_state);
signed int tee_vdec_drv_resume();
signed int tee_vdec_drv_suspend();

typedef struct
{
    uint32_t hal_phyaddr;
    uint32_t share_phyaddr;
    uint32_t pmv_phyaddr;
    uint32_t scd_phyaddr;
    uint32_t ctx_phyaddr;
    uint32_t input_phyaddr;
}PHY_ADDR_INFO_S;

