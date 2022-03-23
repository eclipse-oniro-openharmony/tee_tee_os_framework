/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Implementation of the private GP SCP03 functions for secure flash
 *              communication.
 * Author: aaron.shen
 * Create: 2019/08/20
 */

#ifndef __SECFLASH_SCP03_COMM_H__
#define __SECFLASH_SCP03_COMM_H__

#include <stdint.h>

/*
 * Key Version Number
 * initial/binding key1: secure flash
 * initial/binding key2: weaver
 */
#define SECFLASH_KVN_INITIAL_KEY            0x30
#define SECFLASH_KVN_BINDING_KEY            0x31

#define GP_SUCCESS_SW                       0x9000
#define GP_TDS_SW                           0x69FF

/* GP Command CLA value */
#define GP_CLA_COMMAND                      0x80
#define GP_CLA_COMMAND_SECURE_MESSAGING     0x84

/* GP Command INS value */
#define GP_INS_INITIALIZE_UPDATE            0x30
#define GP_INS_EXTERNAL_AUTHENTICATE        0x31
#define GP_INS_PROGRAM_BINDINGKEY           0x32
#define GP_INS_WRITE_DATA                   0x33
#define GP_INS_READ_DATA                    0x34
#define GP_INS_ERASE_BLOCK                  0x35
#define GP_INS_SET_URS                      0x36

#define SECFLASH_SCARD_TRANS_ID             2
/* secure flash information data length */
#define SECFLASH_VENDOR_ID                  2
#define SECFLASH_INFORMATION_LEN            10
#define SECFLASH_KEY_INFORMATION_LEN        3
#define SECFLASH_PROTOCOL_VERSION_NUMBER    0x03
#define SECFLASH_I_PARAMETER                0x60

#define SECFLASH_FACTORY_NXP_VENDOR_ID      0x4790
#define SECFLASH_FACTORY_ST_VENDOR_ID       0x5354

/*
 * EXTERNAL AUTHENTICATE Reference Control Parameter P1
 * 0x11: C-MAC and R-MAC
 * 0x13: C-DECRYPTION, C-MAC ,and R-MAC
 */
#define GP_SECURITY_LEVEL                   0x11
#define GP_SECURITY_LEVEL_DECRYPT           0x13

/*
 * INITIALIZE UPDATE cmd length
 * '5': CLA-Lc; '8': challenge; '1': Le
 */
#define SECFLASH_INITIALIZE_UPDATE_CMD_LEN          14

/*
 * INITIALIZE UPDATE Response length
 * '10': Secure Flash Information; '3': Key information
 * '16': 2 challenge; '2': sw;
 */
#define SECFLASH_INITIALIZE_UPDATE_RESP_LEN         31

/*
 * EXTERNAL AUTHENTICATE cmd length
 * '5': CLA-Lc; '16': host crypogram and C-MAC;
 */
#define SECFLASH_EXTERNAL_AUTHENTICATE_CMD_LEN      21

/*
 * EXTERNAL AUTHENTICATE Response length
 * '2': sw;
 */
#define SECFLASH_EXTERNAL_AUTHENTICATE_RESP_LEN      2

/*
 * Program BindingKey cmd length
 * '5': CLA-Lc; 'Data': 70; '8': C-MAC
 * Lc: Lc + length of C-MAC +  length of padding(70 padding is 10)
 */
#define SECFLASH_BINDING_PADDING_LEN                 10
#define SECFLASH_BINDING_CMD_LEN                     93
#define SECFLASH_BINDING_DATA_LEN                    70
#define SECFLASH_BINDING_P2                          0x81

/*
 * Program BindingKey Response length
 * '1': KVN; '9': Kcv of keys; '8': R-MAC; '2': SW
 */
#define SECFLASH_PROGRAM_BINDING_RESP_LEN            20
#define SECFLASH_PROGRAM_BINDING_RESP_DATA_LEN       10

/*
 * set urs cmd length
 * '5': CLA-Lc; '8': C-MAC;
 */
#define SECFLASH_SET_URS_CMD_LEN                     13

/*
 * set urs Response length
 * '8': R-MAC; '2': sw;
 */
#define SECFLASH_SET_URS_RESP_LEN                    10

/*
 * Write block cmd max length (16 blocks)
 * '4': CLA-P2; '3': Lc; '2': block count; "16*16": Data; '8': CMAC
 */
#define SECFLASH_WRITE_BLOCK_CMD_LEN                 273
#define SECFLASH_WRITE_COUNT_LEN                     2

/*
 * Write block response length
 * '4': Response Data Field; '8': R-MAC; '2': SW
 */
#define SECFLASH_WRITE_BLOCK_RESP_LEN                14
#define SECFLASH_WRITE_BLOCK_RESP_DATA_LEN           4

/*
 * read block cmd length
 * '5':CLA-LC; '2': LC extended length; '2': Data; '8': C-MAC
 */
#define SECFLASH_READ_BLOCK_CMD_LEN                  17
#define SECFLASH_READ_CMD_DATA_FIELD_LEN             2

/*
 * read block response length
 * '4'-Response Data: 2bytes block index & 2 bytes block count
 * '256*16': read data; '8': R-MAC; '2'-SW
 */
#define SECFLASH_READ_BLOCK_RESP_LEN                 4110
#define SECFLASH_READ_BLOCK_RESP_DATA_OFFSET         4

/*
 * erase block cmd length
 * '5':CLA-LC; '2': Data; '8': C-MAC
 */
#define SECFLASH_ERASE_BLOCK_CMD_LEN                 15
#define SECFLASH_ERASE_CMD_DATA_FIELD_LEN            2
#define SECFLASH_ERASE_BLOCK_RESP_LEN                14
#define SECFLASH_ERASE_BLOCK_RESP_DATA_LEN           4

#define MAX_WRITE_BLOCKS_COUNT                       16
#define MAX_READ_BLOCKS_COUNT                        256
#define PAGE_BLOCKS_COUNT                            64
#define MAX_BLOCKS_COUNT                             9600

/* sepcial module ID */
#define SPECIAL_RIGHT_MODULE            0x2de402e0

/* the err counter  */
#define MAX_ERR_COUNTER                 100000000 /* big enough means don't protect by ourself right now */

/* the right counter  */
#define MAX_RIGHT_COUNTER               10

/* SCP03 channal status */
enum CHANNAL_STATUS {
    /* start to establish the sec channal */
    SECFLASH_INIT_START = 0x3c,
    /* the channal can be used for send/receive data */
    SECFLASH_INIT_FINISHED = 0x96,
    /* the channal got enough ERR and stop supply any services */
    SECFLASH_COUNT_ERR = 0xA5,
};

struct check_info {
    uint8_t ins;
    uint8_t kvn;
    uint32_t response_length;
    uint32_t block_index;
    uint32_t block_count;
};

struct sec_counter {
    uint32_t error_count;
    uint32_t right_count;
    uint16_t encryption_count;
};

uint32_t secflash_get_batch_id(void);
uint32_t secflash_write_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count,
    uint8_t *write_buffer);
uint32_t secflash_read_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count,
    uint8_t *read_buffer, uint32_t buffer_max_length);
uint32_t secflash_erase_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count);
uint32_t secflash_reset(uint8_t reset_type);
uint32_t secflash_power_saving(void);
uint32_t secflash_scp03_init(void);
#endif
