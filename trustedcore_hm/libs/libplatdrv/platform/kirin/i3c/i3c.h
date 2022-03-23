/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: teeos i3c driver code
 *              This program is support for I3C work. include control init,
 *              clock and timing set, read and write data from device.
 * Create: 2019-08-16
 */
#ifndef _I3C_H_
#define _I3C_H_

#include <hisi_boot.h>
#include "soc_acpu_baseaddr_interface.h"

#define BYTES_OF_WORD 4
#define I3C_TIMEOUT_VALUE 200000
#define I3C_OK    0
#define I3C_ERROR (-1)

#define I3C_TRANS_CRC_ERROR      1
#define I3C_TRANS_PARITY_ERROR   2
#define I3C_TRANS_FRAME_ERROR    3
#define I3C_TRANS_BROAD_NACK     4
#define I3C_TRANS_SLVADDR_NACK   5
#define I3C_TRANS_BUF_OVERFLOW   6
#define I3C_TRANS_RD_LEN_ERROR   21
#define I3C_TRANS_BUS_BUSY       22
#define I3C_TRANS_PARA_ERROR     30
#define I3C_TRANS_SLV_NO_REGIST  31
#define I3C_TRANS_TIMEOUT        40
#define I3C_TRANS_TID_ERROR      20

#define SOC_I3C_DATA_BUFFER_THLD_CTRL_TX_EMPTY_BUF_THLD_START  0
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_TX_EMPTY_BUF_THLD_END    2
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_7_3_START           3
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_7_3_END             7
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RX_BUF_THLD_START        8
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RX_BUF_THLD_END          10
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_15_11_START         11
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_15_11_END           15
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_TX_START_THLD_START      16
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_TX_START_THLD_END        18
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_23_19_START         19
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_23_19_END           23
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RX_START_THLD_START      24
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RX_START_THLD_END        26
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_31_27_START         27
#define SOC_I3C_DATA_BUFFER_THLD_CTRL_RSVD_31_27_END           31

#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_STATIC_ADDR_START     0
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_STATIC_ADDR_END       6
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_RSVD_15_7_START           7
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_RSVD_15_7_END             15
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_DYN_ADDR_START        16
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_DYNAMIC_ADDR_END      23
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_RSVD_28_24_START          24
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_RSVD_28_24_END            28
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_NACK_RETRY_CNT_START  29
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_NACK_RETRY_CNT_END    30
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_LEGACY_I2C_DEVICE_START   31
#define SOC_I3C_DEV_ADDR_TABLE_LOC1_LEGACY_I2C_DEVICE_END     31

#define SOC_I3C_QUEUE_STATUS_LEVEL_CMD_QUEUE_EMPTY_LOC_START  0
#define SOC_I3C_QUEUE_STATUS_LEVEL_CMD_QUEUE_EMPTY_LOC_END    7
#define SOC_I3C_QUEUE_STATUS_LEVEL_RESP_BUF_BLR_START         8
#define SOC_I3C_QUEUE_STATUS_LEVEL_RESP_BUF_BLR_END           15
#define SOC_I3C_QUEUE_STATUS_LEVEL_IBI_BUF_BLR_START          16
#define SOC_I3C_QUEUE_STATUS_LEVEL_IBI_BUF_BLR_END            23
#define SOC_I3C_QUEUE_STATUS_LEVEL_IBI_STATUS_CNT_START       24
#define SOC_I3C_QUEUE_STATUS_LEVEL_IBI_STATUS_CNT_END         28
#define SOC_I3C_QUEUE_STATUS_LEVEL_RSVD_START                 29
#define SOC_I3C_QUEUE_STATUS_LEVEL_RSVD_END                   31

#define SOC_I3C_DATA_BUFFER_STATUS_LEVEL_TX_BUF_EMPTY_LOC_START  0
#define SOC_I3C_DATA_BUFFER_STATUS_LEVEL_TX_BUF_EMPTY_LOC_END    7
#define SOC_I3C_DATA_BUFF_STATUS_LV_RX_BUF_BLR_START             8
#define SOC_I3C_DATA_BUFFER_STATUS_LEVEL_RX_BUF_BLR_END          15
#define SOC_I3C_DATA_BUFFER_STATUS_LEVEL_RSVD_START              16
#define SOC_I3C_DATA_BUFFER_STATUS_LEVEL_RSVD_END                31

#define SOC_I3C_RESPONSE_QUEUE_PORT_DATA_LENGTH_OR_DEV_COUNT_START  0
#define SOC_I3C_RESPONSE_QUEUE_PORT_DATA_LENGTH_OR_DEV_COUNT_END    15
#define SOC_I3C_RESPONSE_QUEUE_PORT_TID_START                       24
#define SOC_I3C_RESPONSE_QUEUE_PORT_TID_END                         27
#define SOC_I3C_RESPONSE_QUEUE_PORT_ERR_STATUS_START                28
#define SOC_I3C_RESPONSE_QUEUE_PORT_ERR_STATUS_END                  31

#define SOC_I3C_DEVICE_CTRL_IBA_INCLUDE_START        0
#define SOC_I3C_DEVICE_CTRL_IBA_INCLUDE_END          0
#define SOC_I3C_DEVICE_CTRL_IBA_ARB_BITS_START       1
#define SOC_I3C_DEVICE_CTRL_IBA_ARB_BITS_END         3
#define SOC_I3C_DEVICE_CTRL_I2C_SLAVE_PRESENT_START  7
#define SOC_I3C_DEVICE_CTRL_I2C_SLAVE_PRESENT_END    7
#define SOC_I3C_DEVICE_CTRL_HOT_JOIN_CTRL_START      8
#define SOC_I3C_DEVICE_CTRL_HOT_JOIN_CTRL_END        8
#define SOC_I3C_DEVICE_CTRL_RSVD9_28_START           9
#define SOC_I3C_DEVICE_CTRL_RSVD9_28_END             28
#define SOC_I3C_DEVICE_CTRL_ABORT_START              29
#define SOC_I3C_DEVICE_CTRL_ABORT_END                29
#define SOC_I3C_DEVICE_CTRL_RESUME_START             30
#define SOC_I3C_DEVICE_CTRL_RESUME_END               30
#define SOC_I3C_DEVICE_CTRL_ENABLE_START             31
#define SOC_I3C_DEVICE_CTRL_ENABLE_END               31

#define SOC_I3C_SCL_LCNT_TIMING_I2C_OD_LCNT_START  0
#define SOC_I3C_SCL_LCNT_TIMING_I2C_OD_LCNT_END    15
#define SOC_I3C_SCL_LCNT_TIMING_I3C_OD_LCNT_START  16
#define SOC_I3C_SCL_LCNT_TIMING_I3C_OD_LCNT_END    23
#define SOC_I3C_SCL_LCNT_TIMING_I3C_PP_LCNT_START  24
#define SOC_I3C_SCL_LCNT_TIMING_I3C_PP_LCNT_END    31

#define SOC_I3C_SCL_HCNT_TIMING_I2C_OD_HCNT_START  0
#define SOC_I3C_SCL_HCNT_TIMING_I2C_OD_HCNT_END    7
#define SOC_I3C_SCL_HCNT_TIMING_I3C_OD_HCNT_START  8
#define SOC_I3C_SCL_HCNT_TIMING_I3C_OD_HCNT_END    15
#define SOC_I3C_SCL_HCNT_TIMING_I3C_PP_HCNT_START  16
#define SOC_I3C_SCL_HCNT_TIMING_I3C_PP_HCNT_END    23
#define SOC_I3C_SCL_HCNT_TIMING_RSVD_31_24_START   24
#define SOC_I3C_SCL_HCNT_TIMING_RSVD_31_24_END     31

#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (32 - 1 - (h))))

#define I3C0 0
#define I3C1 1
#define I3C2 2
#define I3C3 3
#define I3C4 4
#define I3C_MAX_NUMS 5

#define I3C_IO_FUNC_I3C    1
#define I3C_IO_FUNC_NORMAL 0

#define I3C_SCL_MAX_FREQ 12500   /* kHZ */
#define I3C_PP_H_MIN 32   /* ns */
#define I3C_PP_L_MIN 32   /* ns */
#define I3C_OD_L_MIN 200  /* ns */

#define I3C_INIT_OK   1
#define I3C_INIT_FAIL 2

#define I3C_INT_SIGNAL 0x01

#define I3C_MSG_WR  0
#define I3C_MSG_RD  1

#define I3C_BROADCAST_CCC  0xFF

#define I3C_SLAVE_ADDR_MASK 0x7F
#define I3C_SLAVE_ADDR_BITS 7

#define I3C_BITS_PER_TRANS  9
#define I3C_BYTES_PER_MS  200
#define I3C_WAIT_COMPLETE_TIMEOUT 1000

#define I3C_CMD_FIFO_DEPTH   2
#define I3C_RES_FIFO_DEPTH   2
#define I3C_RXD_FIFO_DEPTH   64 /* bytes */
#define I3C_TXD_FIFO_DEPTH   64 /* byres */

#define I3C_SLAVE_MAX_NUM  8  /* max = 8, the last used for i2c_dev */
#define I3C_SLAVE_USE_FOR_I3C_NUM  7
#define I3C_SLAVE_USE_FOR_I2C_IDX  7

#define I3C_CMD_ATTR_TRANS       0
#define I3C_CMD_ATTR_TRANS_ARG   1
#define I3C_CMD_ATTR_SHORT_ARG   2
#define I3C_CMD_ATTR_ADDR_ASGN   3

#define I3C_DEV_ADDR_SIZE  0x4
#define I3C_DEV_CHAR_SIZE  0x10

#define I3C_SLVAE_REG_MAX_LEN 0x80000000

#define INTR_BUSOWNER_UPDATE_STAT  BIT(13)
#define INTR_IBI_UPDATED_STAT      BIT(12)
#define INTR_READ_REQ_RECV_STAT    BIT(11)
#define INTR_DEFSLV_STAT           BIT(10)
#define INTR_TRANSFER_ERR_STAT     BIT(9)
#define INTR_DYN_ADDR_ASSGN_STAT   BIT(8)
#define INTR_CCC_UPDATED_STAT      BIT(6)
#define INTR_TRANSFER_ABORT_STAT   BIT(5)
#define INTR_RESP_READY_STAT       BIT(4)
#define INTR_CMD_QUEUE_READY_STAT  BIT(3)
#define INTR_IBI_THLD_STAT         BIT(2)
#define INTR_RX_THLD_STAT          BIT(1)
#define INTR_TX_THLD_STAT          BIT(0)
#define INTR_ALL                (INTR_BUSOWNER_UPDATE_STAT | \
				INTR_IBI_UPDATED_STAT | \
				INTR_READ_REQ_RECV_STAT | \
				INTR_DEFSLV_STAT | \
				INTR_TRANSFER_ERR_STAT | \
				INTR_DYN_ADDR_ASSGN_STAT | \
				INTR_TRANSFER_ABORT_STAT | \
				INTR_CCC_UPDATED_STAT | \
				INTR_RESP_READY_STAT | \
				INTR_CMD_QUEUE_READY_STAT | \
				INTR_IBI_THLD_STAT | \
				INTR_TX_THLD_STAT | \
				INTR_RX_THLD_STAT)

#define INTR_MASTER_MASK        (INTR_TRANSFER_ERR_STAT | \
				INTR_RESP_READY_STAT)

#define INIR_ALL_MASK                0x0

#define I3C_DEVICE_CTRL              0x00
#define DEV_CTRL_RESUME              BIT(30)
#define I3C_COMMAND_PORT             0x0C
#define I3C_CMD_RESPONSE_PORT        0x10
#define RESPONSE_PORT_ERR_STATUS(x)  (((x) & GENMASK(31, 28)) >> 28)
#define I3C_DATA_PORT                0x14
#define I3C_IBI_DATA_PORT            0x18
#define I3C_QUEUE_THLD_CTRL          0x1C
#define QUEUE_THLD_CTRL_RESP_BUF_MASK  GENMASK(15, 8)
#define QUEUE_THLD_CTRL_RESP_BUF(x)    (((x) - 1) << 8)
#define I3C_DATA_BUFF_THLD_CTRL      0x20
#define I3C_IBI_REJECT_CTRL          0x30
#define I3C_INT_STATUS               0x3C
#define I3C_INT_STATUS_ENABLE        0x40
#define I3C_INT_SIGNAL_ENABLE        0x44
#define I3C_QUEUE_STATUS_LEVEL       0x4C
#define QUEUE_STATUS_LEVEL_RESP(x)   (((x) & GENMASK(15, 8)) >> 8)

#define RESPONSE_NO_ERROR               0
#define RESPONSE_ERROR_CRC              1
#define RESPONSE_ERROR_PARITY           2
#define RESPONSE_ERROR_FRAME            3
#define RESPONSE_ERROR_IBA_NACK         4
#define RESPONSE_ERROR_ADDRESS_NACK     5
#define RESPONSE_ERROR_OVER_UNDER_FLOW  6
#define RESPONSE_ERROR_TRANSF_ABORT     8
#define RESPONSE_ERROR_I2C_W_NACK_ERR   9

#define I3C_DATA_BUFF_STATUS_LEVEL   0x50
#define I3C_PRESENT_STATUS           0x54
#define I3C_SCL_HCNT_TIMING          0xB4
#define I3C_SCL_LCNT_TIMING          0xB8
#define I3C_BUS_FREE_TIMING          0xC0
#define I3C_IP_VERSION               0xE0
#define I3C_DEV_CHAR_TABLE           0x200
#define I3C_DEV_ADDR_TABLE           0x300

#define I3C_SCL_FREQ_400K               400
#define I3C_SCL_FREQ_1M                 1000
#define I3C_I2C_FM_TLOW_MIN_NS          1300
#define I3C_I2C_FM_THIGH_MIN_NS         1100
#define I3C_I2C_FMP_TLOW_MIN_NS         500
#define I3C_I2C_FMP_THIGH_MIN_NS        260

#ifndef BIT
#define BIT(x)  (1 << (x))
#endif

#define I3C_TRANS_TID        0x1
#define I3C_SET_DYNADDR_TID  0x3

#define I3C_MODE_I3C  0
#define I3C_MODE_I2C  1

#define I3C_AP_DOMAIN              0
#define I3C_IOMCU_DOMAIN           1
#define NO_NEED_SWITCH_SEC_FLAG    0
#define NEED_SWITCH_SEC_FLAG       1

#define TRANSFER_ERR_INT_STAT_MASK  0x200
#define SEC_I3C                     0
#define UNSEC_I3C                   1
#define I3C_SLAVE_USED              1
#define I3C_SLAVE_UNUSED            0

#ifndef unused
#define unused(x) (void)(x)
#endif

enum i3c_ccc_cmd_enum {
	/* broadcast */
	BROAD_ENEC     = 0x00,
	BROAD_DISEC    = 0x01,
	BROAD_ENTAS0   = 0x02,
	BROAD_ENTAS1   = 0x03,
	BROAD_ENTAS2   = 0x04,
	BROAD_ENTAS3   = 0x05,
	BROAD_RSTDAA   = 0x06,
	BROAD_ENTDAA   = 0x07,
	BROAD_DEFSLVS  = 0x08,
	BROAD_SETMWL   = 0x09,
	BROAD_SETMRL   = 0x0A,
	BROAD_ENTTM    = 0x0B,
	BROAD_ENTHDR0  = 0x20,
	BROAD_ENTHDR1  = 0x21,
	BROAD_ENTHDR2  = 0x22,
	BROAD_ENTHDR3  = 0x23,
	BROAD_ENTHDR4  = 0x24,
	BROAD_ENTHDR5  = 0x25,
	BROAD_ENTHDR6  = 0x26,
	BROAD_ENTHDR7  = 0x27,
	BROAD_ENTHDR8  = 0x28,
	/* direct */
	DIRECT_ENEC      = 0x80,
	DIRECT_DISEC     = 0x81,
	DIRECT_ENTAS0    = 0x82,
	DIRECT_ENTAS1    = 0x83,
	DIRECT_ENTAS2    = 0x84,
	DIRECT_ENTAS3    = 0x85,
	DIRECT_RSTDAA    = 0x86,
	DIRECT_SETDASA   = 0x87,
	DIRECT_SETNEWDA  = 0x88,
	DIRECT_SETMWL    = 0x89,
	DIRECT_SETMRL    = 0x8A,
	DIRECT_GETMWL    = 0x8B,
	DIRECT_GETMRL    = 0x8C,
	DIRECT_GETPID    = 0x8D,
	DIRECT_GETBCR    = 0x8E,
	DIRECT_GETDCR    = 0x8F,
	DIRECT_GETSTATUS = 0x90,
	DIRECT_GETACCMST = 0x91,
	DIRECT_SETBRGTGT = 0x93,
	DIRECT_GETMXDS   = 0x94,
	DIRECT_GETHDRAP  = 0x95,
	DIRECT_SETXTIME  = 0x98,
	DIRECT_GETXTIME  = 0x99,
};

struct tzpc_iomcu_domain_data {
	u32 addr;
	u32 offset;
	u32 mask_bit;
};

struct tzpc_ap_domain_map {
	u32 tzpc_idx;
};

struct i3c_device {
	u8 used;
	u8 dev_idx;
	u8 static_addr;
	u8 dyn_addr;
};

struct i3c_msg {
	u8 slave;
	u8 rw;
	u8 cp;
	u8 cmd;
	u8 *data;
	u32 len;
	u8 mode;
};

struct i3c_adapter {
	struct device *device;
	u32 bus_num;
	u32 clk_rate;

	u32 irq_num;

	/* ip baseaddr */
	u32 baseaddr;

	u32 clk_bit;
	/* clock reg */
	u32 clk_en_reg;
	u32 clk_dis_reg;
	u32 clk_stat_reg;

	u32 rst_bit;
	/* rst reg */
	u32 rst_en_reg;
	u32 rst_dis_reg;
	u32 rst_stat_reg;

	u32 domain;
	u32 tzpc_flag;
	union {
		struct tzpc_iomcu_domain_data tzpc_info;
		struct tzpc_ap_domain_map tzpc_map;
	} tzpc_data;

	/* iomux reg */
	u32 scl_iomux_gpio;
	u32 sda_iomux_gpio;
	u8 iomux_i3c_val;
	u8 iomux_normal_val;

	/* dma request num */
	u8 dma_rx_num;
	u8 dma_tx_num;

	/* scl_output_freq khz */
	u32 scl_od_freq;
	u32 scl_pp_freq;

	/* init status */
	u8 status;

	/* broad reset flag */
	u8 rst_flag;

	/* debug irq cnt each transfer */
	u8 irq_cnt_per_trans;

	/* current trans msg */
	struct i3c_msg *msg;
	u8 msg_num;
	u8 msg_idx;
	u32 resp[I3C_RES_FIFO_DEPTH];

	/* registed slaves info */
	struct i3c_device slaves[I3C_SLAVE_MAX_NUM];
};

struct i3c_trans_cmd {
	u32 cmd_attr : 3; /* bit[2:0] */
	u32 tid      : 4; /* bit[6:3] */
	u32 cmd      : 8; /* bit[14:7] */
	u32 cp       : 1; /* bit[15] */
	u32 dev_idx  : 5; /* bit[20:16] */
	u32 speed    : 3; /* bit[23:21] */
	u32 res0     : 2; /* bit[25:24] */
	u32 roc      : 1; /* bit[26] */
	u32 sdap     : 1; /* bit[27] */
	u32 rw       : 1; /* bit[28] */
	u32 res1     : 1; /* bit[29] */
	u32 toc      : 1; /* bit[30] */
	u32 res2     : 1; /* bit[31] */
};

struct i3c_trans_arg_cmd {
	u32 cmd_attr : 3;  /* bit[2:0] */
	u32 res      : 12; /* bit[14:3] */
	u32 dma      : 1;  /* bit[15] */
	u32 data_len : 16; /* bit[31:16] */
};

struct i3c_short_arg_cmd {
	u32 cmd_attr : 3;  /* bit[2:0] */
	u32 bytes    : 3;  /* bit[5:3] */
	u32 res      : 2;  /* bit[7:6] */
	u32 byte1    : 8;  /* bit[15:8] */
	u32 byte2    : 8;  /* bit[23:16] */
	u32 byte3    : 8;  /* bit[31:24] */
};

struct i3c_addr_asgn_cmd {
	u32 cmd_attr : 3; /* bit[2:0] */
	u32 tid      : 4; /* bit[6:3] */
	u32 cmd      : 8; /* bit[14:7] */
	u32 res0     : 1; /* bit[15] */
	u32 dev_idx  : 5; /* bit[20:16] */
	u32 dev_cnt  : 5; /* bit[25:21] */
	u32 roc      : 1; /* bit[26] */
	u32 res1     : 3; /* bit[29:27] */
	u32 toc      : 1; /* bit[30] */
	u32 res2     : 1; /* bit[31] */
};

union i3c_command {
	u32 value;
	struct i3c_trans_cmd trans_cmd;
	struct i3c_trans_arg_cmd trans_arg_cmd;
	struct i3c_short_arg_cmd short_arg_cmd;
	struct i3c_addr_asgn_cmd addr_asgn_cmd;
};

int hisi_i3c_read(u32 bus_num, u8 slave, u32 reg, u8 *data, u32 len, u8 mode);
int hisi_i3c_write(u32 bus_num, u8 slave, u32 reg, u8 *data, u32 len, u8 mode);
int hisi_i3c_set_dynaddr(u32 bus_num, u32 slv_addr, u32 dynaddr);
int hisi_i3c_clear_software_dynaddr(u32 bus_num, u8 slv_addr);
int hisi_i3c_block_read(u8 bus_num, u8 slave, u8 *data, u16 len, u8 mode);
int hisi_i3c_block_write(u8 bus_num, u8 slave, u8 *data, u16 len, u8 mode);
void hisi_i3c_init(u32 bus_num);
void hisi_i3c_exit(u32 bus_num);

#endif
