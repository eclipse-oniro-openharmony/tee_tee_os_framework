#ifndef _NPU_SMMU_SEC_H
#define _NPU_SMMU_SEC_H

#define NPU_SMMU_READ_STREAM_NUMBER (3)
#define NPU_SMMU_TAG_COMPARE_CASE_NUMBER (6)
#define NPU_SMMU_TOTAL_STREAM_ID_NUMBER (4)

struct smmu_irq_count {
    unsigned int mstr_wdata_burst;
    unsigned int mstr_wr_va_out_of_128byte;
    unsigned int mstr_wr_va_out_of_boundary;
    unsigned int mstr_rd_va_out_of_128byte;
    unsigned int mstr_rd_va_out_of_boundary;
    unsigned int comm_ptw_ns_stat;
    unsigned int comm_ptw_invalid_stat;
    unsigned int comm_ptw_trans_stat;
    unsigned int comm_tlbmiss_stat;
    unsigned int comm_ext_stat;
    unsigned int comm_permis_stat;
};

typedef struct smmu_statistic {
    unsigned int coreID;
    unsigned int read_stream_cmd_total[NPU_SMMU_READ_STREAM_NUMBER];
    unsigned int read_stream_cmd_miss[NPU_SMMU_READ_STREAM_NUMBER];
    unsigned int read_stream_data_total[NPU_SMMU_READ_STREAM_NUMBER];
    unsigned int read_stream_cmd_miss_valid;
    unsigned int read_stream_cmd_miss_pending;
    unsigned int read_stream_cmd_hit_valid_not_slide_window;
    unsigned int read_stream_cmd_hit_valid_slide_window;
    unsigned int read_stream_cmd_hit_pending_not_slide_window;
    unsigned int read_stream_cmd_hit_pending_slide_window;
    unsigned int read_stream_cmd_latency;
    unsigned int write_stream_cmd_total;
    unsigned int write_stream_cmd_miss;
    unsigned int write_stream_data_total;
    unsigned int write_stream_cmd_miss_valid;
    unsigned int write_stream_cmd_miss_pending;
    unsigned int write_stream_cmd_hit_valid_not_slide_window;
    unsigned int write_stream_cmd_hit_valid_slide_window;
    unsigned int write_stream_cmd_hit_pending_not_slide_window;
    unsigned int write_stream_cmd_hit_pending_slide_window;
    unsigned int write_stream_cmd_latency;
    struct smmu_irq_count smmu_irq_count;
}SMMU_STAT_S;

int npu_smmu_mngr_init(void);
void npu_smmu_mngr_exit(void);
void npu_smmu_init(unsigned int coreID);
void npu_smmu_exit(unsigned int coreID);
bool npu_smmu_interrupt_handler(unsigned int coreID);
void npu_smmu_set_stat_en(int enable);
int npu_smmu_get_stat_en(void);
#endif

