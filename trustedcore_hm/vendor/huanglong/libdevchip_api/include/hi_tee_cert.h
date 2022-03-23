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
/** CNcomment:Input data ��Output data���ݴ�С */
#define REG_DATA_NUM                      8
#define REG_DATA_LEN                      4

/** Engine type */
/** CNcomment: �������� */
typedef enum {
    HI_TEE_CERT_KEY_PORT_TSCIPHER     = 0x0,   /** TSCipher */
    HI_TEE_CERT_KEY_PORT_MCIPHER      = 0x1,   /** MCipher */
    HI_TEE_CERT_KEY_PORT_MAX          = 0x2,
} hi_tee_cert_key_port_sel;

/** Timeout type */
/** CNcomment: ��ʱ���� */
typedef enum {
    HI_TEE_CERT_TIMEOUT_DEFAULT, /**< Default timeout. Indicates that the associated command does not write in OTP. */
                                 /**< CNcomment: Ĭ�ϳ�ʱ��������ص������ǲ�����otp��д�����ݵ����� */
    HI_TEE_CERT_TIMEOUT_OTP,     /**< The associated command is writing in OTP memory. */
                                 /**< CNcomment: ������ص�����Ὣ����д�뵽otp�е����� */
    HI_TEE_CERT_LAST_TIMEOUT     /**< Other use. */  /** CNcomment: ������; */
} hi_tee_cert_timeout;

/** Structure of the CERT exchange information */
/** CNcomment:CERT exchange��Ϣ�ṹ */
typedef struct {
    hi_u8 input_data[REG_DATA_LEN * REG_DATA_NUM];
                                       /**< Input data to be written in the 8 32-bit CERT common interface DATA_IN_X
                                            registers. First 4 MSB inputData[0:3] shall be written in DATA_IN_0
                                            register, next 4 MSB inputData[4:7] in DATA_IN_1 register and so on. */
                                       /**< CNcomment: �������ݣ�����д�뵽CERT DATA_IN_X�Ĵ�����8��32�������ݣ�
                                            ǰ4�ֽ�(MSB)д��DATA_IN_0�Ĵ���,������4�ֽ�(MSB)д��DATA_IN_1���Դ����ơ� */
    hi_u8 output_data[REG_DATA_LEN * REG_DATA_NUM];
                                       /**< Buffer where to write values of the 8 32-bit CERT common interface
                                            DATA_OUT_X registers following the processing of a command. */
                                       /**< CNcomment: ����ִ��֮�󣬴˻�������д���CERT DATA_OUT_X�Ĵ�����ȡ��8��
                                            32�������ݡ� */
    hi_u8 status[REG_DATA_LEN];        /**< Buffer where to write the value of the CERT common interface STATUS_AKL
                                            register following the processing of a command. */
                                       /**< CNcomment: ����ִ��֮�󣬴˻�������д���STATUS_AKL�Ĵ�����ȡ�����ݡ� */
    hi_u8 opcodes[REG_DATA_LEN];       /**< Command operation codes to be written in the CERT common interface
                                            COMMAND register. The least significant bit that acts as the command
                                            start bit is already set to 1. */
                                       /**< CNcomment: д��CERT COMMAND�Ĵ�������������룬���һ��bit����Ϊ1��Ч�� */
    hi_tee_cert_timeout time_out;      /**< This field characterizes the processing duration of the command. It is
                                            not expressed as a duration. Associated timeout values is to be defined
                                            by the entity in charge of developing the CERT driver. This field is
                                            mainly used to know whether the command is going to write in OTP or not. */
                                       /**< CNcomment: ��������Ĵ���ʱ��, ��������������ʱ��ĳ��ȣ����峬ʱʱ��������
                                            ��������ֶ���Ҫ���ڸ�֪���������Ƿ���дotp����� */
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
/** CNcomment:CERT CTRL��Ϣ�ṹ */
typedef struct {
    hi_handle handle;                  /**< Target module handle, address information included */
    hi_bool is_even;                   /**< Type of key odd or even */
    hi_tee_crypto_alg engine;          /**< Target crypto engine */
    hi_tee_cert_key_port_sel port_sel; /**< Port select */
    hi_tee_cert_secure_config sec_cfg; /**< Secure configuration. */
} hi_tee_cert_key_data;

/** Structure of CERT resource */
/** CNcomment: CERT��Դ�ṹ */
typedef struct {
    hi_handle res_handle;  /**< Cert resource handle */  /**< CNcomment: Cert ��� */
} hi_tee_cert_res_handle;
/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API Declaration *****************************/
/** \addtogroup      CERT */
/** @{ */  /** <!--[CERT] */

/**
\brief Initializes the CERT module.CNcomment:��ʼ��CERTģ�顣CNend
\attention \n
Before using CERT, you must call this application programming interface (API).\n
The error code HI_SUCCESS is returned if this API is called repeatedly.
CNcomment:�ڽ���PLCIPHER��ز���ǰӦ�����ȵ��ñ��ӿ�\n
�ظ����ñ��ӿڷ��سɹ���CNend
\param  N/A.CNcomment:�ޡ�CNend
\retval ::HI_SUCCESS Success. CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\see \n
N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_init(hi_void);

/**
\brief Deinitializes the CERT module. CNcomment:ȥ��ʼ��CERTģ�顣CNend
\attention \n
After this API is called, the CERT module is stopped, and the CERT resources used by the process are released.\n
This API is valid when it is called for the first time. If this API is called repeatedly,
the error code HI_SUCCESS is returned.
CNcomment:���ñ��ӿ�ֹͣʹ��CERTģ�飬���ͷű�������ռ�õ�CERT��Դ\n
���ӿڵ�һ�ε��������ã��ظ����÷��سɹ���CNend
\param  N/A.CNcomment:�ޡ�CNend
\retval ::HI_SUCCESS Success CNcomment:�ɹ���CNend
\retval ::HI_FAILURE Calling this API fails. CNcomment:APIϵͳ����ʧ�ܡ�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_deinit(hi_void);

/**
\brief Send the key on the bus to the subsequent encryption or descryption engine.
CNcomment:�������ϵ�key�͸��󼶼ӽ������档CNend
\param[in] ctl_data     Pointer to the structure of the CERT CTRL information.
CNcomment:ָ�����ͣ�ָ��CERT CTRL��Ϣ���ƽṹ�塣CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_use_key(hi_tee_cert_key_data *ctl_data);

/**
\brief Get AKL metadata when AKL key is pendding on the bus.
CNcomment:������������Կʱ���ȡmetadata��CNend
\param[in] metadata   Pointer to the metadata information.
CNcomment:ָ�����ͣ�ָ��CERT metedata��Ϣ��CNend
\retval ::HI_SUCCESS  Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_CERT_NO_KEY_GENERATION  No key pendding on the bus. CNcomment:����Կ���ɡ�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_get_metadata(hi_u32 *metadata);

/**
\brief Reset cert. CNcomment:��λCERTģ�顣CNend
\retval ::HI_SUCCESS  Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_reset(hi_void);

/**
\brief This function reserves the CERT resource for exclusive use to the caller.
CNcomment:��ȡcert����Դ��CNend
\param[out] res_handle     Handle assigned to the CERT resource.
CNcomment:ָ�����ͣ�ָ��CERT ��Դ�ľ����CNend
\retval ::HI_SUCCESS  Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_lock(hi_tee_cert_res_handle **res_handle);

/**
\brief This function releases the CERT resource previously locked by hi_tee_cert_lock()
CNcomment:�ͷű�����hi_tee_cert_lock��ס����Դ��CNend
\param[in] res_handle     Pointer to the structure of the CERT resource handle.
CNcomment:ָ�����ͣ�ָ��CERT ��Դ�ľ����CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_unlock(hi_tee_cert_res_handle *res_handle);

/**
\brief
This function is used to send a series of commands to the CERT block, for chipset information or operating OTP.
CNcomment:�˺���������CERT IP����һϵ�е������ȡоƬ��Ϣ���߲���OTP�� CNend
\param[in] res_handle Handle to the CERT resource.
CNcomment:ָ�����ͣ�ָ��CERT ��Դ�ľ����CNend
\param[in] num_of_command   Number of commands to be processed by the CERT block.
CNcomment: ����CERT���������Ŀ����CNend
\param[in,out] commands   This structure is used to accommodate input parameters of each command \n
as well as resulting output. The memory is allocated by the caller.
CNcomment: �ýṹ���ڴ洢ÿ���������������Լ����ɵ�������ڴ��ɵ����߷��䡣CNend
\param[out] num_of_proccessed_commands   Number of commands actually processed by the CERT block.
CNcomment:ʵ��ִ�е�����������CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_CERT_NOT_INIT  The CERT module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_CERT_INVALID_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_CERT_TIME_OUT  The timeout has expired and the CERT block is still processing a command.
CNcomment:CERTһֱ��ִ��ĳ������³�ʱ��CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_cert_exchange(hi_tee_cert_res_handle *res_handle, hi_size_t num_of_command,
                            const hi_tee_cert_command *commands, hi_size_t *num_of_proccessed_commands);

/** @} */  /** <!-- ==== API declaration end ==== */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif   /* __HI_TEE_CERT__ */

