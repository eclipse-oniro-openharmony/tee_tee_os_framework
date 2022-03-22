#ifndef HISI_SMMU_H
#define HISI_SMMU_H

/*
 * Hisi fake mmu registers with 16 bytes.
 * Just for ACPU communication with AI CPU by gic.
 */
#define HISI_MMU_IDR0                      0x0
#define HISI_MMU_IDR1                      0x4

#define HISI_SEC_IDR1_ST_X0                0
#define HISI_SEC_IDR1_ST_X1                0x4


#define HISI_MMU_ADDR                      0x8
#define HISI_MMU_SIZE                      0xC

#define HISI_SEC_SMMU_FEAT_2_LVL_STRTAB (1 << 0)
#define HISI_SEC_SMMU_FEAT_2_LVL_CDTAB (1 << 1)
#define HISI_SEC_SMMU_FEAT_TT_LE (1 << 2)
#define HISI_SEC_SMMU_FEAT_TT_BE (1 << 3)
#define HISI_SEC_SMMU_FEAT_PRI (1 << 4)
#define HISI_SEC_SMMU_FEAT_ATS (1 << 5)
#define HISI_SEC_SMMU_FEAT_SEV (1 << 6)
#define HISI_SEC_SMMU_FEAT_MSI (1 << 7)
#define HISI_SEC_SMMU_FEAT_COHERENCY (1 << 8)
#define HISI_SEC_SMMU_FEAT_TRANS_S1 (1 << 9)
#define HISI_SEC_SMMU_FEAT_TRANS_S2 (1 << 10)
#define HISI_SEC_SMMU_FEAT_STALLS (1 << 11)
#define HISI_SEC_SMMU_FEAT_HYP (1 << 12)

/*module base addr */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define HISI_TOP_CTL_BASE 0x30000
#define HISI_TCU_CACHE_BASE 0x31000
#define HISI_TCU_PG0_BASE 0x0
#else
#define HISI_TOP_CTL_BASE                  0
#define HISI_TCU_CACHE_BASE                0x1000
#define HISI_MASTER_0_BASE                 0x10000
#define HISI_MASTER_1_BASE                 0x14000
#define HISI_TCU_PG0_BASE                  0x20000
#define HISI_TCU_PG1_BASE                  0x30000
#define HISI_TCU_PG2_BASE                  0x40000
#define HISI_TCU_PG3_BASE                  0x50000
#define HISI_TBU_PG0_BASE                  0x60000
#define HISI_TBU_PG1_BASE                  0x70000
#endif

/* Sec TCU CFG offset */
#define HISI_SEC_TCU_OFFSET                0x8000

/* TCU CACHE reg */
#define TTW_OPT_FUNC_BYPASS                HISI_TCU_CACHE_BASE
#define CACHELINE_INV_ALL                 (HISI_TCU_CACHE_BASE + 0x4)
#define CACHELINE_INV_ALL_FIELD           (1 << 0)

/* smmu master reg */
#define SMMU_MSTR_GLB_BYPASS               0
#define SMMU_MSTR_SID_BYPASS_VAL           3

#define SMMU_MSTR_SMRX_START_0             0x28
#define SMMU_MSTR_SMRX_START_1             0x2c
#define SMMU_MSTR_SMRX_START_2             0x30


#define SMMU_MSTR_INPT_SEL                 0x28
#define END_REG_SEL                       (1 << 1)
#define SMR_START_SEL                     (1 << 0)

#define SMMU_MSTR_INTMASK                  0x40
#define SMMU_MSTR_INTRAW                   0x44
#define SMMU_MSTR_INTSTAT                  0x48
#define SMMU_MSTR_INTCLR                   0x4c
#define WDATA_BURST_CLR                   (1 << 4)
#define WR_VA_ERR1_CLR                    (1 << 3)
#define WR_VA_ERR0_CLR                    (1 << 2)
#define RD_VA_ERR1_CLR                    (1 << 1)
#define RD_VA_ERR0_CLR                    (1 << 0)

#define SMMU_MSTR_SMRX_0(m)               (0x4 * (m) + 0x100)
#define SSID_V_MASK_EN                    (1 << 1)
#define MSTR_BYPASS                       (1 << 0)
#define SMMU_MSTR_SMRX_1(m)               (0x4 * (m) + 0x260)
#define SMMU_MSTR_SMRX_2(m)               (0x4 * (m) + 0x3c0)
#define SMMU_MSTR_SMRX_3(m)               (0x4 * (m) + 0x520)
#define SMMU_MSTR_END_ACK_0               (0x1c)
#define SMMU_MSTR_END_ACK_1               (0x20)

/* TBU reg */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define TCU_CACHE_INV                     (1 << 0)
#define TBU_IS_CONNECTED                  (1 << 0)
#define TBU_MAX_NUM                        14
#else
#define SMMU_TBU_CR                       (HISI_TBU_PG0_BASE + 0)
#define TBU_EN_REQ                        (1 << 0)

#define SMMU_TBU_CRACK                    (HISI_TBU_PG0_BASE + 0x4)
#define TBU_EN_ACK                        (1 << 0)
#define TBU_CONNECTED                     (1 << 1)
#endif

#define SMMU_TBU_CR_S                     (HISI_TBU_PG0_BASE + 0x8E18)

/* TOP reg */
#define SMMU_LP_REQ                       (HISI_TOP_CTL_BASE + 0)
#define TCU_QREQN_CG                      (1 << 0)
#define TCU_QREQN_PD                      (1 << 1)

#define SMMU_LP_ACK                       (HISI_TOP_CTL_BASE + 0x4)
#define TCU_QACCEPTN_CG                   (1 << 0)
#define TCU_QACCEPTN_PD                   (1 << 4)

#define SMMU_IRPT_MASK_NS                 (HISI_TOP_CTL_BASE + 0x70)
#define TCU_EVENT_TO_MASK                 (1 << 5)
#define SMMU_IRPT_RAW_NS                  (HISI_TOP_CTL_BASE + 0x74)
#define SMMU_IRPT_STAT_NS                 (HISI_TOP_CTL_BASE + 0x78)

#define TCU_EVENT_Q_IRQ                   (1 << 0)
#define TCU_CMD_SYNC_IRQ                  (1 << 1)
#define TCU_GERROR_IRQ                    (1 << 2)
#define SMMU_IRPT_CLR_NS                  (HISI_TOP_CTL_BASE + 0x7c)
#define TCU_EVENT_Q_IRQ_CLR               (1 << 0)
#define TCU_CMD_SYNC_IRQ_CLR              (1 << 1)
#define TCU_GERROR_IRQ_CLR                (1 << 2)

#define SMMU_IRPT_MASK_S                  (HISI_TOP_CTL_BASE + 0x80)
#define SMMU_IRPT_RAW_S                   (HISI_TOP_CTL_BASE + 0x84)
#define SMMU_IRPT_STAT_S                  (HISI_TOP_CTL_BASE + 0x88)
#define SMMU_IRPT_CLR_S                   (HISI_TOP_CTL_BASE + 0x8c)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define SMMU_TCU_CTRL_SCR                 (HISI_TOP_CTL_BASE + 0x90)
#define SMMU_TCU_CTRL_SCR_UARCH_NS        (1 << 0)
#define HISI_SEC_S_SMMU_TCU_SCR           (HISI_TCU_PG0_BASE + 0x8e18)
#define HISI_SEC_S_SMMU_TCU_INIT          (HISI_TCU_PG0_BASE + 0x803c)
#define HISI_SEC_TCU_NODE_STATUS          (HISI_TCU_PG0_BASE + 0x9400)
#define HISI_SEC_S_SMMU_TCU_SCR_NS         9
#endif

/* TCU registers */
#define HISI_SEC_SMMU_IDR0                (HISI_TCU_PG0_BASE + 0x0)
#define HISI_SEC_SMMU_IDR0_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x0)
#define HISI_SEC_IDR0_ST_LVL_SHIFT         27
#define HISI_SEC_IDR0_ST_LVL_MASK          0x3
#define HISI_SEC_IDR0_ST_LVL_2LVL         (1 << HISI_SEC_IDR0_ST_LVL_SHIFT)
#define HISI_SEC_IDR0_STALL_MODEL         (3 << 24)
#define HISI_SEC_IDR0_TTENDIAN_SHIFT       21
#define HISI_SEC_IDR0_TTENDIAN_MASK        0x3
#define HISI_SEC_IDR0_TTENDIAN_LE         (2 << HISI_SEC_IDR0_TTENDIAN_SHIFT)
#define HISI_SEC_IDR0_TTENDIAN_BE         (3 << HISI_SEC_IDR0_TTENDIAN_SHIFT)
#define HISI_SEC_IDR0_TTENDIAN_MIXED      (0 << HISI_SEC_IDR0_TTENDIAN_SHIFT)
#define HISI_SEC_IDR0_CD2L                (1 << 19)
#define HISI_SEC_IDR0_VMID16              (1 << 18)
#define HISI_SEC_IDR0_PRI                 (1 << 16)
#define HISI_SEC_IDR0_SEV                 (1 << 14)
#define HISI_SEC_IDR0_MSI                 (1 << 13)
#define HISI_SEC_IDR0_ASID16              (1 << 12)
#define HISI_SEC_IDR0_ATS                 (1 << 10)
#define HISI_SEC_IDR0_HYP                 (1 << 9)
#define HISI_SEC_IDR0_COHACC              (1 << 4)
#define HISI_SEC_IDR0_TTF_SHIFT            2
#define HISI_SEC_IDR0_TTF_MASK             0x3
#define HISI_SEC_IDR0_TTF_AARCH64         (2 << HISI_SEC_IDR0_TTF_SHIFT)
#define HISI_SEC_IDR0_TTF_AARCH32_64      (3 << HISI_SEC_IDR0_TTF_SHIFT)
#define HISI_SEC_IDR0_S1P                 (1 << 1)
#define HISI_SEC_IDR0_S2P                 (1 << 0)

#define HISI_SEC_SMMU_IDR1                (HISI_TCU_PG0_BASE + 0x4)
#define HISI_SEC_SMMU_IDR1_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x4)
#define HISI_SEC_IDR1_TABLES_PRESET       (1 << 30)
#define HISI_SEC_IDR1_QUEUES_PRESET       (1 << 29)
#define HISI_SEC_IDR1_REL                 (1 << 28)
#define HISI_SEC_IDR1_CMDQ_SHIFT           21
#define HISI_SEC_IDR1_CMDQ_MASK            0x1f
#define HISI_SEC_IDR1_EVTQ_SHIFT           16
#define HISI_SEC_IDR1_EVTQ_MASK            0x1f
#define HISI_SEC_IDR1_PRIQ_SHIFT           11
#define HISI_SEC_IDR1_PRIQ_MASK            0x1f
#define HISI_SEC_IDR1_SSID_SHIFT           6
#define HISI_SEC_IDR1_SSID_MASK            0x1f
#define HISI_SEC_IDR1_SSID_BITS            5
#define HISI_SEC_IDR1_SID_SHIFT            0
#define HISI_SEC_IDR1_SID_MASK             0x3f

#define HISI_SEC_SMMU_IDR2_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x4)
#define HISI_SEC_SMMU_IDR3_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x8)
#define HISI_SEC_SMMU_IDR4_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xc)

/* no sec idr5 reg, multiplexing with nonsec idr5 */
#define HISI_SEC_SMMU_IDR5                (HISI_TCU_PG0_BASE + 0x14)
#define HISI_SEC_IDR5_STALL_MAX_SHIFT      16
#define HISI_SEC_IDR5_STALL_MAX_MASK       0xffff
#define HISI_SEC_IDR5_GRAN64K             (1 << 6)
#define HISI_SEC_IDR5_GRAN16K             (1 << 5)
#define HISI_SEC_IDR5_GRAN4K              (1 << 4)
#define HISI_SEC_IDR5_OAS_SHIFT            0
#define HISI_SEC_IDR5_OAS_MASK             0x7
#define HISI_SEC_IDR5_OAS_32_BIT          (0 << HISI_SEC_IDR5_OAS_SHIFT)
#define HISI_SEC_IDR5_OAS_36_BIT          (1 << HISI_SEC_IDR5_OAS_SHIFT)
#define HISI_SEC_IDR5_OAS_40_BIT          (2 << HISI_SEC_IDR5_OAS_SHIFT)
#define HISI_SEC_IDR5_OAS_42_BIT          (3 << HISI_SEC_IDR5_OAS_SHIFT)
#define HISI_SEC_IDR5_OAS_44_BIT          (4 << HISI_SEC_IDR5_OAS_SHIFT)
#define HISI_SEC_IDR5_OAS_48_BIT          (5 << HISI_SEC_IDR5_OAS_SHIFT)

#define HISI_SEC_SMMU_IIDR_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x18)
#define HISI_SEC_SMMU_AIDR_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x1c)
#define HISI_SEC_SMMU_CR0_S               (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x20)

#define CR0_CMDQEN                        (1 << 3)
#define CR0_EVTQEN                        (1 << 2)
#define CR0_PRIQEN                        (1 << 1)
#define CR0_SMMUEN                        (1 << 0)

#define HISI_SEC_SMMU_CR0ACK_S            (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x24)

#define HISI_SEC_SMMU_CR1_S               (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x28)
#define CR1_SH_NSH                         0
#define CR1_SH_OSH                         2
#define CR1_SH_ISH                         3
#define CR1_CACHE_NC                       0
#define CR1_CACHE_WB                       1
#define CR1_CACHE_WT                       2
#define CR1_TABLE_SH_SHIFT                 10
#define CR1_TABLE_OC_SHIFT                 8
#define CR1_TABLE_IC_SHIFT                 6
#define CR1_QUEUE_SH_SHIFT                 4
#define CR1_QUEUE_OC_SHIFT                 2
#define CR1_QUEUE_IC_SHIFT                 0

#define HISI_SEC_SMMU_CR2_S               (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x2c)
#define CR2_PTM                           (1 << 2)
#define CR2_RECINVSID                     (1 << 1)
#define CR2_E2H                           (1 << 0)

#define HISI_SEC_SMMU_INIT_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x3c)
#define INIT_INVALD_ALL                   (1 << 0)

#define HISI_SEC_SMMU_STATUS_S            (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x40)
#define HISI_SEC_SMMU_GBPA_S              (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x44)
#define HISI_SEC_SMMU_AGBPA_S             (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x48)
#define HISI_SEC_SMMU_IRQ_CTRL_S          (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x50)
#define IRQ_CTRL_EVTQ_IRQEN               (1 << 2)
#define IRQ_CTRL_PRIQ_IRQEN               (1 << 1)
#define IRQ_CTRL_GERROR_IRQEN             (1 << 0)

#define HISI_SEC_SMMU_IRQ_CTRLACK_S       (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x54)

#define HISI_SEC_SMMU_GERROR_S            (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x60)

#define HISI_SEC_GERROR_SFM_ERR                    (1 << 8)
#define HISI_SEC_GERROR_MSI_GERROR_ABT_ERR         (1 << 7)
#define HISI_SEC_GERROR_MSI_PRIQ_ABT_ERR           (1 << 6)
#define HISI_SEC_GERROR_MSI_EVTQ_ABT_ERR           (1 << 5)
#define HISI_SEC_GERROR_MSI_CMDQ_ABT_ERR           (1 << 4)
#define HISI_SEC_GERROR_PRIQ_ABT_ERR               (1 << 3)
#define HISI_SEC_GERROR_EVTQ_ABT_ERR               (1 << 2)
#define HISI_SEC_GERROR_CMDQ_ERR                   (1 << 0)
#define HISI_SEC_GERROR_ERR_MASK                    0xfd

#define HISI_SEC_SMMU_GERRORN_S           (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x64)

#define HISI_SEC_SMMU_GERROR_IRQ_CFG0_S   (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x68)
#define HISI_SEC_SMMU_GERROR_IRQ_CFG1_S   (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x70)
#define HISI_SEC_SMMU_GERROR_IRQ_CFG2_S   (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x74)

#define HISI_SEC_SMMU_STRTAB_BASE_S       (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x80)
#define HISI_SEC_SMMU_STRTAB_BASE_H_S     (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x84)
#define HISI_SEC_STRTAB_BASE_RA                    (1ULL << 62)
#define HISI_SEC_STRTAB_BASE_ADDR_SHIFT             6
#define HISI_SEC_STRTAB_BASE_ADDR_MASK              0xffffffc0

#define HISI_SEC_SMMU_STRTAB_BASE_CFG_S   (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x88)

#define HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_SHIFT     0
#define HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_MASK      0x3f
#define HISI_SEC_STRTAB_BASE_CFG_SPLIT_SHIFT        6
#define HISI_SEC_STRTAB_BASE_CFG_SPLIT_MASK         0x1f
#define HISI_SEC_STRTAB_BASE_CFG_FMT_SHIFT          16
#define HISI_SEC_STRTAB_BASE_CFG_FMT_MASK           0x3
#define HISI_SEC_STRTAB_BASE_CFG_FMT_LINEAR        (0 << HISI_SEC_STRTAB_BASE_CFG_FMT_SHIFT)
#define HISI_SEC_STRTAB_BASE_CFG_FMT_2LVL          (1 << HISI_SEC_STRTAB_BASE_CFG_FMT_SHIFT)

#define HISI_SEC_SMMU_CMDQ_BASE_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x90)
#define HISI_SEC_SMMU_CMDQ_BASE_H_S       (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x94)
#define HISI_SEC_SMMU_CMDQ_PROD_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x98)
#define HISI_SEC_SMMU_CMDQ_CONS_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x9c)

#define HISI_SEC_SMMU_EVTQ_BASE_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xa0)
#define HISI_SEC_SMMU_EVTQ_BASE_H_S       (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xa4)
#define HISI_SEC_SMMU_EVTQ_PROD_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xa8)
#define HISI_SEC_SMMU_EVTQ_CONS_S         (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xac)
#define HISI_SEC_SMMU_EVTQ_IRQ_CFG0_S     (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xb0)
#define HISI_SEC_SMMU_EVTQ_IRQ_CFG1_S     (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xb8)
#define HISI_SEC_SMMU_EVTQ_IRQ_CFG2_S     (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0xbc)


#define HISI_SEC_SMMU_NODE_STATUS     	  (HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + 0x9400)

/* Common MSI config fields */
#define MSI_CFG0_ADDR_SHIFT                2
#define MSI_CFG0_ADDR_MASK                 0x3fffffffffffULL
#define MSI_CFG2_SH_SHIFT                  4
#define MSI_CFG2_SH_NSH                   (0ULL << MSI_CFG2_SH_SHIFT)
#define MSI_CFG2_SH_OSH                   (2ULL << MSI_CFG2_SH_SHIFT)
#define MSI_CFG2_SH_ISH                   (3ULL << MSI_CFG2_SH_SHIFT)
#define MSI_CFG2_MEMATTR_SHIFT             0
#define MSI_CFG2_MEMATTR_DEVICE_nGnRE     (0x1 << MSI_CFG2_MEMATTR_SHIFT)

#define Q_IDX(q, p)                       ((p) & ((1 << (q)->max_n_shift) - 1))
#define Q_WRP(q, p)                       ((p) & (1 << (q)->max_n_shift))
#define Q_OVERFLOW_FLAG                   ((unsigned)1 << 31)
#define Q_OVF(q, p)                       (((unsigned)p) & Q_OVERFLOW_FLAG)
#define Q_ENT(q, p)                       ((q)->base + Q_IDX(q, p) * (q)->ent_dwords)

#define Q_BASE_RWA                        (1ULL << 62)
#define Q_BASE_ADDR_SHIFT                  5
#define Q_BASE_ADDR_MASK                   0xffffffe0ULL
#define Q_BASE_LOG2SIZE_SHIFT              0
#define Q_BASE_LOG2SIZE_MASK               0x1fULL
#define Q_BASE_HIGH_ADDR_SHIFT             32

/*
 * Stream table.
 *
 * Linear: Enough to cover 1 << IDR1.SIDSIZE entries
 * 2lvl: 128k L1 entries,
 *       256 lazy entries per table (each table covers a PCI bus)
 */
#define HISI_SEC_STRTAB_L1_SZ_SHIFT                 20
#define HISI_SEC_STRTAB_SPLIT                       8

#define HISI_SEC_STRTAB_L1_DESC_DWORDS              1
#define HISI_SEC_STRTAB_L1_DESC_DWORDS_LOG2         0
#define HISI_SEC_STRTAB_L1_DESC_SPAN_SHIFT          0
#define HISI_SEC_STRTAB_L1_DESC_SPAN_MASK           0x1fULL
#define HISI_SEC_STRTAB_L1_DESC_L2PTR_SHIFT         6
#define HISI_SEC_STRTAB_L1_DESC_L2PTR_MASK          0x3ffffffffffULL

#define HISI_SEC_STRTAB_STE_DWORDS                  8
#define HISI_SEC_STRTAB_STE_DWORDS_LOG2             3
#define HISI_SEC_STRTAB_STE_0_V                    (1ULL << 0)
#define HISI_SEC_STRTAB_STE_0_CFG_SHIFT             1
#define HISI_SEC_STRTAB_STE_0_CFG_MASK              0x7ULL
#define HISI_SEC_STRTAB_STE_0_CFG_ABORT            (0ULL << HISI_SEC_STRTAB_STE_0_CFG_SHIFT)
#define HISI_SEC_STRTAB_STE_0_CFG_BYPASS           (4ULL << HISI_SEC_STRTAB_STE_0_CFG_SHIFT)
#define HISI_SEC_STRTAB_STE_0_CFG_S1_TRANS         (5ULL << HISI_SEC_STRTAB_STE_0_CFG_SHIFT)
#define HISI_SEC_STRTAB_STE_0_CFG_S2_TRANS         (6ULL << HISI_SEC_STRTAB_STE_0_CFG_SHIFT)

#define HISI_SEC_STRTAB_STE_0_S1FMT_SHIFT           4
#define HISI_SEC_STRTAB_STE_0_S1FMT_LINEAR         (0ULL << HISI_SEC_STRTAB_STE_0_S1FMT_SHIFT)
#define HISI_SEC_STRTAB_STE_0_S1CTXPTR_SHIFT        6
#define HISI_SEC_STRTAB_STE_0_S1CTXPTR_MASK         0x3ffffffffffULL
#define HISI_SEC_STRTAB_STE_0_S1CDMAX_SHIFT         59
#define HISI_SEC_STRTAB_STE_0_S1CDMAX_MASK          0x1fULL

#define HISI_SEC_STRTAB_STE_1_S1C_CACHE_NC          0ULL
#define HISI_SEC_STRTAB_STE_1_S1C_CACHE_WBRA        1ULL
#define HISI_SEC_STRTAB_STE_1_S1C_CACHE_WT          2ULL
#define HISI_SEC_STRTAB_STE_1_S1C_CACHE_WB          3ULL
#define HISI_SEC_STRTAB_STE_1_S1C_SH_NSH            0ULL
#define HISI_SEC_STRTAB_STE_1_S1C_SH_OSH            2ULL
#define HISI_SEC_STRTAB_STE_1_S1C_SH_ISH            3ULL
#define HISI_SEC_STRTAB_STE_1_S1CIR_SHIFT           2
#define HISI_SEC_STRTAB_STE_1_S1COR_SHIFT           4
#define HISI_SEC_STRTAB_STE_1_S1CSH_SHIFT           6

#define HISI_SEC_STRTAB_STE_1_S1STALLD             (1ULL << 27)

#define HISI_SEC_STRTAB_STE_1_EATS_ABT              0ULL
#define HISI_SEC_STRTAB_STE_1_EATS_TRANS            1ULL
#define HISI_SEC_STRTAB_STE_1_EATS_S1CHK            2ULL
#define HISI_SEC_STRTAB_STE_1_EATS_SHIFT            28

#define HISI_SEC_STRTAB_STE_1_STRW_NSEL1            0ULL
#define HISI_SEC_STRTAB_STE_1_STRW_EL2              2ULL
#define HISI_SEC_STRTAB_STE_1_STRW_SHIFT            30

#define HISI_SEC_STRTAB_STE_2_S2VMID_SHIFT          0
#define HISI_SEC_STRTAB_STE_2_S2VMID_MASK           0xffffULL
#define HISI_SEC_STRTAB_STE_2_VTCR_SHIFT            32
#define HISI_SEC_STRTAB_STE_2_VTCR_MASK             0x7ffffULL
#define HISI_SEC_STRTAB_STE_2_S2AA64               (1ULL << 51)
#define HISI_SEC_STRTAB_STE_2_S2ENDI               (1ULL << 52)
#define HISI_SEC_STRTAB_STE_2_S2PTW                (1ULL << 54)
#define HISI_SEC_STRTAB_STE_2_S2R                  (1ULL << 58)

#define HISI_SEC_STRTAB_STE_3_S2TTB_SHIFT           4
#define HISI_SEC_STRTAB_STE_3_S2TTB_MASK            0xfffffffffffULL

/* Context descriptor (stage-1 only) */
#define CTXDESC_CD_DWORDS                  8
#define CTXDESC_CD_0_TCR_T0SZ_SHIFT        0
#define HISI_SECTCR_T0SZ_SHIFT             0
#define HISI_SECTCR_T0SZ_MASK              0x1fULL
#define CTXDESC_CD_0_TCR_TG0_SHIFT         6
#define HISI_SECTCR_TG0_SHIFT              14
#define HISI_SECTCR_TG0_MASK               0x3ULL
#define CTXDESC_CD_0_TCR_IRGN0_SHIFT       8
#define HISI_SECTCR_IRGN0_SHIFT            8
#define HISI_SECTCR_IRGN0_MASK             0x3ULL
#define CTXDESC_CD_0_TCR_ORGN0_SHIFT       10
#define HISI_SECTCR_ORGN0_SHIFT            10
#define HISI_SECTCR_ORGN0_MASK             0x3ULL
#define CTXDESC_CD_0_TCR_SH0_SHIFT         12
#define HISI_SECTCR_SH0_SHIFT              12
#define HISI_SECTCR_SH0_MASK               0x3ULL
#define CTXDESC_CD_0_TCR_EPD0_SHIFT        14
#define HISI_SECTCR_EPD0_SHIFT             7
#define HISI_SECTCR_EPD0_MASK              0x1ULL
#define CTXDESC_CD_0_TCR_EPD1_SHIFT        30
#define HISI_SECTCR_EPD1_SHIFT             23
#define HISI_SECTCR_EPD1_MASK              0x1ULL

#define CTXDESC_CD_0_ENDI                 (1ULL << 15)
#define CTXDESC_CD_0_V                    (1ULL << 31)
#define HISI_SEC_SMMU_MAX_ASIDS           (1 << 16)
#define HISI_SEC_SMMU_MAX_SIDS            0xff
#define CTXDESC_CD_MAX_SSIDS              (1 << 4)

#define CTXDESC_CD_0_TCR_IPS_SHIFT         32
#define HISI_SECTCR_IPS_SHIFT              32
#define HISI_SECTCR_IPS_MASK               0x7ULL
#define CTXDESC_CD_0_TCR_TBI0_SHIFT        38
#define HISI_SECTCR_TBI0_SHIFT             37
#define HISI_SECTCR_TBI0_MASK              0x1ULL

#define CTXDESC_CD_0_AA64                 (1ULL << 41)
#define CTXDESC_CD_0_S                    (1ULL << 44)
#define CTXDESC_CD_0_R                    (1ULL << 45)
#define CTXDESC_CD_0_A                    (1ULL << 46)
#define CTXDESC_CD_0_ASET_SHIFT            47
#define CTXDESC_CD_0_ASET_SHARED          (0ULL << CTXDESC_CD_0_ASET_SHIFT)
#define CTXDESC_CD_0_ASET_PRIVATE         (1ULL << CTXDESC_CD_0_ASET_SHIFT)
#define CTXDESC_CD_0_ASID_SHIFT            48
#define CTXDESC_CD_0_ASID_MASK             0xffffULL

#define CTXDESC_CD_1_TTB0_SHIFT            4
#define CTXDESC_CD_1_TTB0_MASK             0xfffffffffffULL
#define CTXDESC_CD_3_MAIR_SHIFT            0

/* Convert between AArch64 (CPU) TCR format and SMMU CD format */
#define HISI_SEC_SMMU_TCR2CD(tcr, fld) \
	(((tcr) >> HISI_SECTCR_##fld##_SHIFT & HISI_SECTCR_##fld##_MASK) \
	 << CTXDESC_CD_0_TCR_##fld##_SHIFT)

/* Command queue */
#define CMDQ_ENT_DWORDS                    2
#define CMDQ_MAX_SZ_SHIFT                  8

#define CMDQ_ERR_SHIFT                     24
#define CMDQ_ERR_MASK                      0x7f
#define CMDQ_ERR_CERROR_NONE_IDX           0
#define CMDQ_ERR_CERROR_ILL_IDX            1
#define CMDQ_ERR_CERROR_ABT_IDX            2

#define CMDQ_0_OP_SHIFT                    0
#define CMDQ_0_OP_MASK                     0xffULL
#define CMDQ_0_SSEC                       (1ULL << 10)
#define CMDQ_0_SSV                        (1ULL << 11)

#define CMDQ_PREFETCH_0_SID_SHIFT          32
#define CMDQ_PREFETCH_1_SIZE_SHIFT         0
#define CMDQ_PREFETCH_1_ADDR_MASK         ~0xfffULL

#define CMDQ_CFGI_0_CD_SHIFT               12
#define CMDQ_CFGI_0_CD_MASK                0xfffff000ULL
#define CMDQ_CFGI_0_SID_SHIFT              32
#define CMDQ_CFGI_0_SID_MASK               0xffffffffULL
#define CMDQ_CFGI_1_LEAF                  (1ULL << 0)
#define CMDQ_CFGI_1_RANGE_SHIFT            0
#define CMDQ_CFGI_1_RANGE_MASK             0x1fULL

#define CMDQ_TLBI_0_VMID_SHIFT             32
#define CMDQ_TLBI_0_ASID_SHIFT             48
#define CMDQ_TLBI_1_LEAF                  (1ULL << 0)
#define CMDQ_TLBI_1_VA_MASK               ~0xfffULL
#define CMDQ_TLBI_1_IPA_MASK               0xfffffffff000ULL

#define CMDQ_PRI_0_SSID_SHIFT              12
#define CMDQ_PRI_0_SSID_MASK               0xfffffULL
#define CMDQ_PRI_0_SID_SHIFT               32
#define CMDQ_PRI_0_SID_MASK                0xffffffffULL
#define CMDQ_PRI_1_GRPID_SHIFT             0
#define CMDQ_PRI_1_GRPID_MASK              0x1ffULL
#define CMDQ_PRI_1_RESP_SHIFT              12
#define CMDQ_PRI_1_RESP_DENY              (0ULL << CMDQ_PRI_1_RESP_SHIFT)
#define CMDQ_PRI_1_RESP_FAIL              (1ULL << CMDQ_PRI_1_RESP_SHIFT)
#define CMDQ_PRI_1_RESP_SUCC              (2ULL << CMDQ_PRI_1_RESP_SHIFT)

#define CMDQ_SYNC_0_CS_SHIFT               12
#define CMDQ_SYNC_0_CS_NONE               (0ULL << CMDQ_SYNC_0_CS_SHIFT)
#define CMDQ_SYNC_0_CS_SEV                (2ULL << CMDQ_SYNC_0_CS_SHIFT)

/* Event queue */
#define EVTQ_ENT_DWORDS                    4
#define EVTQ_MAX_SZ_SHIFT                  7

#define EVTQ_0_ID_SHIFT                    0
#define EVTQ_0_ID_MASK                     0xffULL

#define EVTQ_TYPE_TRANSL_FORBIDDEN         0x07
#define EVTQ_TYPE_WALK_EABT                0x0b
#define EVTQ_TYPE_TRANSLATION              0x10
#define EVTQ_TYPE_ADDR_SIZE                0x11
#define EVTQ_TYPE_ACCESS                   0x12
#define EVTQ_TYPE_PERMISSION               0x13

#define EVTQ_TYPE_WITH_ADDR(id)            ((EVTQ_TYPE_TRANSLATION == (id))   \
                                            ||(EVTQ_TYPE_WALK_EABT == (id))   \
                                            ||(EVTQ_TYPE_TRANSL_FORBIDDEN == (id)) \
                                            ||(EVTQ_TYPE_ADDR_SIZE == (id))   \
                                            ||(EVTQ_TYPE_ACCESS == (id))      \
                                            ||(EVTQ_TYPE_PERMISSION == (id)))

/* High-level queue structures */
#define HISI_SEC_SMMU_POLL_TIMEOUT_US      100000

#define CMDQ_OP_PREFETCH_CFG               0x1
#define CMDQ_OP_CFGI_STE                   0x3
#define CMDQ_OP_CFGI_STE_RANGE             0x4
#define CMDQ_OP_CFGI_ALL                   CMDQ_OP_CFGI_STE_RANGE
#define CMDQ_OP_CFGI_CD                    0x5
#define CMDQ_OP_CFGI_CD_ALL                0x6
#define CMDQ_OP_TLBI_NH_ASID               0x11
#define CMDQ_OP_TLBI_NH_VA                 0x12
#define CMDQ_OP_TLBI_EL2_ALL               0x20
#define CMDQ_OP_TLBI_S12_VMALL             0x28
#define CMDQ_OP_TLBI_S2_IPA                0x2a
#define CMDQ_OP_TLBI_NSNH_ALL              0x30
#define CMDQ_OP_RESUME                     0x44
#define CMDQ_OP_STALL_TERM                 0x45
#define CMDQ_OP_CMD_SYNC                   0x46

#define HISI_SEC_LPAE_TCR_EPD1 (1 << 23)

#define HISI_SEC_LPAE_TCR_T0SZ_SHIFT 0

#define HISI_SEC_LPAE_TCR_IPS_SHIFT 32

#define HISI_SEC_LPAE_TCR_PS_32_BIT 0x0ULL
#define HISI_SEC_LPAE_TCR_PS_36_BIT 0x1ULL
#define HISI_SEC_LPAE_TCR_PS_40_BIT 0x2ULL
#define HISI_SEC_LPAE_TCR_PS_42_BIT 0x3ULL
#define HISI_SEC_LPAE_TCR_PS_44_BIT 0x4ULL
#define HISI_SEC_LPAE_TCR_PS_48_BIT 0x5ULL

#define HISI_SEC_LPAE_MAIR_ATTR_SHIFT(n) ((n) << 3)
#define HISI_SEC_LPAE_MAIR_ATTR_DEVICE 0x04
#define HISI_SEC_LPAE_MAIR_ATTR_NC 0x44
#define HISI_SEC_LPAE_MAIR_ATTR_WBRWA 0xff
#define HISI_SEC_LPAE_MAIR_ATTR_IDX_NC 0
#define HISI_SEC_LPAE_MAIR_ATTR_IDX_CACHE 1
#define HISI_SEC_LPAE_MAIR_ATTR_IDX_DEV 2

#define HISI_SMMU_INVALID_SID             (0xff)
#define HISI_VAL_MASK                     (0xffffffff)
#define MAX_CHECK_TIMES                    100
#define HISI_SID_MAX_BITS                  6
#define HISI_SSID_MAX_BITS                 6
#define HISI_SMMU_ADDR_SIZE_32             32
#define HISI_SMMU_ADDR_SIZE_36             36
#define HISI_SMMU_ADDR_SIZE_40             40
#define HISI_SMMU_ADDR_SIZE_42             42
#define HISI_SMMU_ADDR_SIZE_44             44
#define HISI_SMMU_ADDR_SIZE_48             48
#define HISI_SMMU_ID_SIZE_8                8
#define HISI_SMMU_ID_SIZE_16               16

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define HISI_SMMUV3_BASE_0                 0xe5f80000  /* sdma */
#if defined(WITH_KIRIN990_CS2)
#define HISI_SMMUV3_IRQ_0                  614
#else
#define HISI_SMMUV3_IRQ_0                  486
#endif
#define HISI_SMMUV3_BYPASS_WR_AI_0         HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_RD_AI_0         HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_WR_SDMA_0       57
#define HISI_SMMUV3_BYPASS_RD_SDMA_0       31
#define HISI_SMMUV3_MSTR0_END0_VAL_0       0xFF800000
#define HISI_SMMUV3_MSTR0_END1_VAL_0       0x3FE0000
#define HISI_SMMUV3_MSTR1_END0_VAL_0       0xFF800000
#define HISI_SMMUV3_MSTR1_END1_VAL_0       0x3FE0000

#define HISI_SMMUV3_BASE_1                 0xe5f00000  /* aicore0 */
#if defined(WITH_KIRIN990_CS2)
#define HISI_SMMUV3_IRQ_1                  616
#else
#define HISI_SMMUV3_IRQ_1                  488
#endif
#define HISI_SMMUV3_BYPASS_WR_AI_1         48
#define HISI_SMMUV3_BYPASS_RD_AI_1         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_RD_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_MSTR0_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR0_END1_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END1_VAL_1       0x1ffff

#define HISI_SMMUV3_BASE_2                 0xe5e80000  /* aicore1 */
#define HISI_SMMUV3_IRQ_2                  612
#define HISI_SMMUV3_BYPASS_WR_AI_2         48
#define HISI_SMMUV3_BYPASS_RD_AI_2         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_2       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_RD_SDMA_2       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_MSTR0_END0_VAL_2       0x1ffff
#define HISI_SMMUV3_MSTR0_END1_VAL_2       0x1ffff
#define HISI_SMMUV3_MSTR1_END0_VAL_2       0x1ffff
#define HISI_SMMUV3_MSTR1_END1_VAL_2       0x1ffff

#define HISI_AICPU_IRQ                     500
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define HISI_SMMUV3_BASE_0                 0xe5f00000
#define HISI_SMMUV3_IRQ_0                  422
#define HISI_SMMUV3_BYPASS_WR_AI_0         48
#define HISI_SMMUV3_BYPASS_RD_AI_0         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_0       57
#define HISI_SMMUV3_BYPASS_RD_SDMA_0       31
#define HISI_SMMUV3_MSTR0_END0_VAL_0       0x1FFFC
#define HISI_SMMUV3_MSTR0_END1_VAL_0       0x1FFFF
#define HISI_SMMUV3_MSTR1_END0_VAL_0       0xFF800000
#define HISI_SMMUV3_MSTR1_END1_VAL_0       0x3FE0000

#define HISI_SMMUV3_BASE_1                 0xe5f00000
#define HISI_SMMUV3_IRQ_1                  488
#define HISI_SMMUV3_BYPASS_WR_AI_1         48
#define HISI_SMMUV3_BYPASS_RD_AI_1         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_RD_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_MSTR0_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR0_END1_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END1_VAL_1       0x1ffff

#define HISI_AICPU_IRQ                     500
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define HISI_SMMUV3_BASE_0                 0xe5f40000
#define HISI_SMMUV3_IRQ_0                  642
#define HISI_SMMUV3_BYPASS_WR_AI_0         48
#define HISI_SMMUV3_BYPASS_RD_AI_0         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_0       57
#define HISI_SMMUV3_BYPASS_RD_SDMA_0       31
#define HISI_SMMUV3_MSTR0_END0_VAL_0       0x1FFFC
#define HISI_SMMUV3_MSTR0_END1_VAL_0       0x1FFFF
#define HISI_SMMUV3_MSTR1_END0_VAL_0       0xFF800000
#define HISI_SMMUV3_MSTR1_END1_VAL_0       0x3FE0000

#define HISI_SMMUV3_BASE_1                 0xe5f00000
#define HISI_SMMUV3_IRQ_1                  488
#define HISI_SMMUV3_BYPASS_WR_AI_1         48
#define HISI_SMMUV3_BYPASS_RD_AI_1         16
#define HISI_SMMUV3_BYPASS_WR_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_BYPASS_RD_SDMA_1       HISI_SEC_SMMU_MAX_SIDS
#define HISI_SMMUV3_MSTR0_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR0_END1_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END0_VAL_1       0x1ffff
#define HISI_SMMUV3_MSTR1_END1_VAL_1       0x1ffff

#define HISI_AICPU_IRQ                     500
#endif

#endif
