/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key ladder driver
 * Author: Linux SDK team
 * Create: 2019-8-26
 */

#ifndef __HI_TEE_CERT__
#define __HI_TEE_CERT__

#include "hi_type_dev.h"
#include "hi_tee_security.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*************************** Structure Definition ****************************/
/** \addtogroup      CERT  */
/** @{ */  /** <!-- [CERT] */

/** Input and Output data Num */
/** CNcomment:Input data 和Output data数据大小 */
#define REG_DATA_NUM                      8
#define REG_DATA_LEN                      4

/** Engine type */
/** CNcomment: 引擎类型 */
typedef enum {
    HI_TEE_CERT_KEY_PORT_TSCIPHER     = 0x0,   /** TSCipher */
    HI_TEE_CERT_KEY_PORT_MCIPHER      = 0x1,   /** MCipher */
    HI_TEE_CERT_KEY_PORT_MAX          = 0x2,
} hi_tee_cert_key_port_sel;

/** Timeout type */
/** CNcomment: 超时类型 */
typedef enum {
    HI_TEE_CERT_TIMEOUT_DEFAULT, /**< Default timeout. Indicates that the associated command does not write in OTP. */
                                 /**< CNcomment: 默认超时，表明相关的命令是不会向otp中写入数据的命令 */
    HI_TEE_CERT_TIMEOUT_OTP,     /**< The associated command is writing in OTP memory. */
                                 /**< CNcomment: 表明相关的命令会将数据写入到otp中的命令 */
    HI_TEE_CERT_LAST_TIMEOUT     /**< Other use. */  /** CNcomment: 其他用途 */
} hi_tee_cert_timeout;

/** Structure of the CERT exchange information */
/** CNcomment:CERT exchange信息结构 */
typedef struct {
    hi_u8 input_data[REG_DATA_LEN * REG_DATA_NUM];
                                       /**< Input data to be written in the 8 32-bit CERT common interface DATA_IN_X
                                            registers. First 4 MSB inputData[0:3] shall be written in DATA_IN_0
                                            register, next 4 MSB inputData[4:7] in DATA_IN_1 register and so on. */
                                       /**< CNcomment: 输入数据，用于写入到CERT DATA_IN_X寄存器的8个32比特数据，
                                            前4字节(MSB)写在DATA_IN_0寄存器,接下来4字节(MSB)写入DATA_IN_1，以此类推。 */
    hi_u8 output_data[REG_DATA_LEN * REG_DATA_NUM];
                                       /**< Buffer where to write values of the 8 32-bit CERT common interface
                                            DATA_OUT_X registers following the processing of a command. */
                                       /**< CNcomment: 命令执行之后，此缓存用于写入从CERT DATA_OUT_X寄存器读取的8个
                                            32比特数据。 */
    hi_u8 status[REG_DATA_LEN];        /**< Buffer where to write the value of the CERT common interface STATUS_AKL
                                            register following the processing of a command. */
                                       /**< CNcomment: 命令执行之后，此缓存用于写入从STATUS_AKL寄存器读取的数据。 */
    hi_u8 opcodes[REG_DATA_LEN];       /**< Command operation codes to be written in the CERT common interface
                                            COMMAND register. The least significant bit that acts as the command
                                            start bit is already set to 1. */
                                       /**< CNcomment: 写入CERT COMMAND寄存器的命令操作码，最后一个bit设置为1有效。 */
    hi_tee_cert_timeout time_out;      /**< This field characterizes the processing duration of the command. It is
                                            not expressed as a duration. Associated timeout values is to be defined
                                            by the entity in charge of developing the CERT driver. This field is
                                            mainly used to know whether the command is going to write in OTP or not. */
                                       /**< CNcomment: 描述命令的处理时间, 并不是描述具体时间的长度，具体超时时间由驱动
                                            负责这个字段主要用于感知操作命令是否是写otp的命令。 */
} hi_tee_cert_command;

/* Define the structure of content key security configurations. */
typedef struct {
    hi_bool key_secure;               /* Support secure key or not */
    hi_bool dest_buf_sec_support;     /* The destination buffer of target engine can be secure. */
    hi_bool dest_buf_non_sec_support; /* The destination buffer of target engine can be non-secure. */
    hi_bool src_buf_sec_support;      /* The source buffer of target engine can be secure. */
    hi_bool src_buf_non_sec_support;  /* The source buffer of target engine can be non-secure. */
} hi_tee_cert_secure_config;

/** Structure of the CERT CTRL information */
/** CNcomment:CERT CTRL信息结构 */
typedef struct {
    hi_handle handle;                  /**< Target module handle, address information included */
    hi_bool is_even;                   /**< Type of key odd or even */
    hi_tee_crypto_alg engine;          /**< Target crypto engine */
    hi_tee_cert_key_port_sel port_sel; /**< Port select */
    hi_tee_cert_secure_config sec_cfg; /**< Secure configuration. */
} hi_tee_cert_key_data;

/** Structure of CERT resource */
/** CNcomment: CERT资源结构 */
typedef struct {
    hi_handle res_handle;  /**< Cert resource handle */  /**< CNcomment: Cert 句柄 */
} hi_tee_cert_res_handle;
/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API Declaration *****************************/
/** \addtogroup      CERT */
/** @{ */  /** <!--[CERT] */

/**
\brief Initializes the CERT module.CNcomment:初始化CERT模块。CNend
\attention \n
Before using CERT, you must call this application programming interface (API).\n
The error code HI_SUCCESS is returned if this API is called repeatedly.
CNcomment:在进行PLCIPHER相关操作前应该首先调用本接口\n
重复调用本接口返回成功。CNend
\param  N/A.CNcomment:无。CNend
\retval ::HI_SUCCESS Success. CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\see \n
N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_init(hi_void);

/**
\brief Deinitializes the CERT module. CNcomment:去初始化CERT模块。CNend
\attention \n
After this API is called, the CERT module is stopped, and the CERT resources used by the process are released.\n
This API is valid when it is called for the first time. If this API is called repeatedly,
the error code HI_SUCCESS is returned.
CNcomment:调用本接口停止使用CERT模块，并释放本进程所占用的CERT资源\n
本接口第一次调用起作用，重复调用返回成功。CNend
\param  N/A.CNcomment:无。CNend
\retval ::HI_SUCCESS Success CNcomment:成功。CNend
\retval ::HI_FAILURE Calling this API fails. CNcomment:API系统调用失败。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_deinit(hi_void);

/**
\brief Send the key on the bus to the subsequent encryption or descryption engine.
CNcomment:将总线上的key送给后级加解密引擎。CNend
\param[in] ctl_data     Pointer to the structure of the CERT CTRL information.
CNcomment:指针类型，指向CERT CTRL信息控制结构体。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_use_key(hi_tee_cert_key_data *ctl_data);

/**
\brief Get AKL metadata when AKL key is pendding on the bus.
CNcomment:当总线生成密钥时候获取metadata。CNend
\param[in] metadata   Pointer to the metadata information.
CNcomment:指针类型，指向CERT metedata信息。CNend
\retval ::HI_SUCCESS  Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_CERT_NO_KEY_GENERATION  No key pendding on the bus. CNcomment:无密钥生成。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_get_metadata(hi_u32 *metadata);

/**
\brief Reset cert. CNcomment:复位CERT模块。CNend
\retval ::HI_SUCCESS  Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:模块没有初始化。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_reset(hi_void);

/**
\brief This function reserves the CERT resource for exclusive use to the caller.
CNcomment:获取cert的资源。CNend
\param[out] res_handle     Handle assigned to the CERT resource.
CNcomment:指针类型，指向CERT 资源的句柄。CNend
\retval ::HI_SUCCESS  Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_lock(hi_tee_cert_res_handle **res_handle);

/**
\brief This function releases the CERT resource previously locked by hi_tee_cert_lock()
CNcomment:释放被函数hi_tee_cert_lock锁住的资源。CNend
\param[in] res_handle     Pointer to the structure of the CERT resource handle.
CNcomment:指针类型，指向CERT 资源的句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_unlock(hi_tee_cert_res_handle *res_handle);

/**
\brief
This function is used to send a series of commands to the CERT block, for chipset information or operating OTP.
CNcomment:此函数用于想CERT IP发送一系列的命令，获取芯片信息或者操作OTP。 CNend
\param[in] res_handle Handle to the CERT resource.
CNcomment:指针类型，指向CERT 资源的句柄。CNend
\param[in] num_of_command   Number of commands to be processed by the CERT block.
CNcomment: 操作CERT的命令的条目数。CNend
\param[in,out] commands   This structure is used to accommodate input parameters of each command \n
as well as resulting output. The memory is allocated by the caller.
CNcomment: 该结构用于存储每个命令的输入参数以及生成的输出。内存由调用者分配。CNend
\param[out] num_of_proccessed_commands   Number of commands actually processed by the CERT block.
CNcomment:实际执行的命令条数。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_CERT_TIME_OUT  The timeout has expired and the CERT block is still processing a command.
CNcomment:CERT一直在执行某个命令导致超时。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_cert_exchange(hi_tee_cert_res_handle *res_handle, hi_size_t num_of_command,
                            const hi_tee_cert_command *commands, hi_size_t *num_of_proccessed_commands);

/** @} */  /** <!-- ==== API declaration end ==== */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif   /* __HI_TEE_CERT__ */

