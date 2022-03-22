#ifndef __BSP_MEMORY_LAYOUT_H__
#define __BSP_MEMORY_LAYOUT_H__

/**
 * @brief 获取DDR内存布局
 * @par 描述:
 * 获取DDR内存布局
 * @param[in] name: 要获取的DDR内存段名称（名称在DTS中注册）name长度不超过16字节
 * ------名称-------------说明-----------------------使用范围--------
 * "mdm_dts_ddr"      modem DTB空间               所有版本
 * "mdm_ddr"          modem运行空间               所有版本
 * "sec_share_ddr"    安全共享内存                5000以前手机版本
 * "early_log_ddr"    早期维测空间                5010及以后版本
 * "bl31_ddr"         BL3运行空间                 5010及以后版本
 * "secos_ddr"        安全OS运行空间              5010及以后版本
 * "mntn_ddr"         维测内存空间                5010及以后版本
 * "share_nsro_ddr"   非安全只读不可写共享内存    5010及以后版本
 * "share_unsec_ddr"  非安全共享内存              5010及以后版本
 * "share_sec_ddr"    安全共享内存                5010及以后版本
 * "mcu_ddr"          M3备份恢复空间              5010及以后版本
 * "mdm_rsv_ddr"      预留内存空间                5010及以后版本
 * "tvp_ddr"          TVP运行空间                 5010和laguna
 * "pde_ddr"          PDE镜像空间                 5010及以后版本
 * "hifi_ddr"         HIFI运行空间                5010及以后版本
 * "rf_sub6g_ddr"     RFIC sub6g镜像              5010及以后版本
 * "rf_hf_ddr"        RFIC高频镜像                5010及以后版本
 * "acore_ddr"        AP 运行空间                 5010及以后版本
 * "acore_dts_ddr"    AP DTS空间                  5010及以后版本
 * "socp_bbpds_ddr"   SOCP数采空间                5010及以后版本
 * ------------------------------------------------------------------
 * @param[in] size: ddr内存段的大小
 * @retval 0 申请失败
 * @retval 其它 返回DDR内存段的物理地址
 */
unsigned long mdrv_mem_region_get(const char *name, unsigned int *size);

#endif /* __BSP_MEMORY_LAYOUT_H__ */ 