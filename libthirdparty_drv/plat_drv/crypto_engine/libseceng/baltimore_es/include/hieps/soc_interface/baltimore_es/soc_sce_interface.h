/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_sce_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:28
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nManager�Ĵ����ֲ�_SCE.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_SCE_INTERFACE_H__
#define __SOC_SCE_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 �궨��
*****************************************************************************/

/****************************************************************************
                     (1/1) reg_define
 ****************************************************************************/
/* �Ĵ���˵�����ӽ���IPѡ��,�ӽ��ܹ�����ʽ�Ĵ���
   λ����UNION�ṹ:  SOC_SCE_MODE_UNION */
#define SOC_SCE_MODE_ADDR(base)                       ((base) + (0x0000))

/* �Ĵ���˵����������շ������ݳ���
   λ����UNION�ṹ:  SOC_SCE_RX_DAT_LEN_UNION */
#define SOC_SCE_RX_DAT_LEN_ADDR(base)                 ((base) + (0x0004))

/* �Ĵ���˵���������������
   λ����UNION�ṹ:  SOC_SCE_CFG_UNION */
#define SOC_SCE_CFG_ADDR(base)                        ((base) + (0x0008))

/* �Ĵ���˵��������״̬�Ĵ���
   λ����UNION�ṹ:  SOC_SCE_BUSY_DONE_UNION */
#define SOC_SCE_BUSY_DONE_ADDR(base)                  ((base) + (0x000C))

/* �Ĵ���˵����FIFOˮ���ϱ�
   λ����UNION�ṹ:  SOC_SCE_FIFO_LINE_UNION */
#define SOC_SCE_FIFO_LINE_ADDR(base)                  ((base) + (0x0010))

/* �Ĵ���˵�����ӽ������濪ʼ��־
   λ����UNION�ṹ:  SOC_SCE_STR_RUN_UNION */
#define SOC_SCE_STR_RUN_ADDR(base)                    ((base) + (0x0014))

/* �Ĵ���˵�����ԳƼӽ��������ԭʼalarm�źţ�����ǰ��
   λ����UNION�ṹ:  SOC_SCE_ALARM_UNION */
#define SOC_SCE_ALARM_ADDR(base)                      ((base) + (0x0018))

/* �Ĵ���˵�����ԳƼӽ�������alarm ����ʹ��
   λ����UNION�ṹ:  SOC_SCE_ALARM_MASK_EN_UNION */
#define SOC_SCE_ALARM_MASK_EN_ADDR(base)              ((base) + (0x001C))

/* �Ĵ���˵�����ԳƼӽ�������alarm�����ź�
   λ����UNION�ṹ:  SOC_SCE_ALARM_CLR_UNION */
#define SOC_SCE_ALARM_CLR_ADDR(base)                  ((base) + (0x0020))

/* �Ĵ���˵�����ԳƼӽ��������alarm�źţ����κ�
   λ����UNION�ṹ:  SOC_SCE_ALARM_MASK_UNION */
#define SOC_SCE_ALARM_MASK_ADDR(base)                 ((base) + (0x0024))

/* �Ĵ���˵�������淢�ͷ������ݳ���
   λ����UNION�ṹ:  SOC_SCE_TX_DAT_LEN_UNION */
#define SOC_SCE_TX_DAT_LEN_ADDR(base)                 ((base) + (0x0030))

/* �Ĵ���˵����SCE�Ĵ��������ź�
   λ����UNION�ṹ:  SOC_SCE_REG_LOCK_UNION */
#define SOC_SCE_REG_LOCK_ADDR(base)                   ((base) + (0x0034))

/* �Ĵ���˵����������յ�һ�����ݷ���
   λ����UNION�ṹ:  SOC_SCE_DIN_UNION */
#define SOC_SCE_DIN_ADDR(base, n)                     ((base) + (0x0040+(n)*4))

/* �Ĵ���˵����������յ�IV IN
   λ����UNION�ṹ:  SOC_SCE_IVIN_UNION */
#define SOC_SCE_IVIN_ADDR(base, n)                    ((base) + (0x0080+(n)*4))

/* �Ĵ���˵��������������һ�����ݷ���
   λ����UNION�ṹ:  SOC_SCE_DOUT_UNION */
#define SOC_SCE_DOUT_ADDR(base, n)                    ((base) + (0x00C0+(n)*4))

/* �Ĵ���˵��������������IV OUT
   λ����UNION�ṹ:  SOC_SCE_IVOUT_UNION */
#define SOC_SCE_IVOUT_ADDR(base, n)                   ((base) + (0x0100+(n)*4))

/* �Ĵ���˵�������ļ�ʹ�ܱ�־
   λ����UNION�ṹ:  SOC_SCE_POWER_DISTURB_EN_UNION */
#define SOC_SCE_POWER_DISTURB_EN_ADDR(base)           ((base) + (0x0140))

/* �Ĵ���˵�������ļ���������־
   λ����UNION�ṹ:  SOC_SCE_POWER_DISTURB_RUN_UNION */
#define SOC_SCE_POWER_DISTURB_RUN_ADDR(base)          ((base) + (0x0144))

/* �Ĵ���˵��������MD5���й��ļ���ʱ�ĳ�ʼ����ֵ
   λ����UNION�ṹ:  SOC_SCE_POWER_DISTURB_DIN_UNION */
#define SOC_SCE_POWER_DISTURB_DIN_ADDR(base, n)       ((base) + (0x0180+(n)*4))

/* �Ĵ���˵����αroundʹ���ź�
   λ����UNION�ṹ:  SOC_SCE_REDROUND_EN_UNION */
#define SOC_SCE_REDROUND_EN_ADDR(base)                ((base) + (0x01C0))

/* �Ĵ���˵����αround����
   λ����UNION�ṹ:  SOC_SCE_REDROUND_NUM_UNION */
#define SOC_SCE_REDROUND_NUM_ADDR(base)               ((base) + (0x01C4))

/* �Ĵ���˵����SM4����������Ƿ�仯���ʹ��
   λ����UNION�ṹ:  SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION */
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_ADDR(base)        ((base) + (0x01C8))

/* �Ĵ���˵����HASH�ֶ�ʱ�Ƿ�padding�ı�־
   λ����UNION�ṹ:  SOC_SCE_HASH_PADDING_EN_UNION */
#define SOC_SCE_HASH_PADDING_EN_ADDR(base)            ((base) + (0x01CC))

/* �Ĵ���˵����EFUSEC�����SCE���ź�
   λ����UNION�ṹ:  SOC_SCE_EFUSEC_DBG_UNION */
#define SOC_SCE_EFUSEC_DBG_ADDR(base)                 ((base) + (0x01D0))

/* �Ĵ���˵�����Գ�IPʹ��
   λ����UNION�ṹ:  SOC_SCE_IP_EN_UNION */
#define SOC_SCE_IP_EN_ADDR(base)                      ((base) + (0x01D4))

/* �Ĵ���˵��������hash������ܵ����ݳ���
   λ����UNION�ṹ:  SOC_SCE_HASH_DATA_LENTH_ALL_UNION */
#define SOC_SCE_HASH_DATA_LENTH_ALL_ADDR(base)        ((base) + (0x0200))

/* �Ĵ���˵����CTRģʽ������յļ������ĳ�ֵ
   λ����UNION�ṹ:  SOC_SCE_CNTIN_UNION */
#define SOC_SCE_CNTIN_ADDR(base, n)                   ((base) + (0x0240+(n)*4))

/* �Ĵ���˵����CTRģʽ��������ļ������ĳ�ֵ
   λ����UNION�ṹ:  SOC_SCE_CNTOUT_UNION */
#define SOC_SCE_CNTOUT_ADDR(base, n)                  ((base) + (0x0280+(n)*4))

/* �Ĵ���˵��������ȡ���ݵ�Դ��ַ
   λ����UNION�ṹ:  SOC_SCE_SRC_ADDR_UNION */
#define SOC_SCE_SRC_ADDR_ADDR(base)                   ((base) + (0x02C0))

/* �Ĵ���˵�������������ݵ�Ŀ�ĵ�ַ
   λ����UNION�ṹ:  SOC_SCE_DES_ADDR_UNION */
#define SOC_SCE_DES_ADDR_ADDR(base)                   ((base) + (0x02C4))

/* �Ĵ���˵�������ݿ�ָʾ�ź�
   λ����UNION�ṹ:  SOC_SCE_IV_BYPASS_UNION */
#define SOC_SCE_IV_BYPASS_ADDR(base)                  ((base) + (0x02CC))

/* �Ĵ���˵�����ж����μĴ���
   λ����UNION�ṹ:  SOC_SCE_INT_SCE_MASK_EN_UNION */
#define SOC_SCE_INT_SCE_MASK_EN_ADDR(base)            ((base) + (0x02D0))

/* �Ĵ���˵�����ж�״̬�Ĵ���(���κ��ϱ���״̬)
   λ����UNION�ṹ:  SOC_SCE_INT_SCE_MASK_UNION */
#define SOC_SCE_INT_SCE_MASK_ADDR(base)               ((base) + (0x02D4))

/* �Ĵ���˵�����ж�����ǰ״̬�Ĵ���(ʵ��״̬)
   λ����UNION�ṹ:  SOC_SCE_INT_SCE_UNION */
#define SOC_SCE_INT_SCE_ADDR(base)                    ((base) + (0x02D8))

/* �Ĵ���˵�����ж�����Ĵ���
   λ����UNION�ṹ:  SOC_SCE_INT_SCE_CLR_UNION */
#define SOC_SCE_INT_SCE_CLR_ADDR(base)                ((base) + (0x02DC))

/* �Ĵ���˵�����ն�fifo��д����
   λ����UNION�ṹ:  SOC_SCE_FIFO_RX_WDATA_UNION */
#define SOC_SCE_FIFO_RX_WDATA_ADDR(base)              ((base) + (0x02E0))

/* �Ĵ���˵�����ն�fifo�Ķ�����
   λ����UNION�ṹ:  SOC_SCE_FIFO_RX_RDATA_UNION */
#define SOC_SCE_FIFO_RX_RDATA_ADDR(base)              ((base) + (0x02E4))

/* �Ĵ���˵��������fifo��д����
   λ����UNION�ṹ:  SOC_SCE_FIFO_TX_WDATA_UNION */
#define SOC_SCE_FIFO_TX_WDATA_ADDR(base)              ((base) + (0x02E8))

/* �Ĵ���˵��������fifo�Ķ�����
   λ����UNION�ṹ:  SOC_SCE_FIFO_TX_RDATA_UNION */
#define SOC_SCE_FIFO_TX_RDATA_ADDR(base)              ((base) + (0x02EC))

/* �Ĵ���˵����gm�Ŀ����ź�
   λ����UNION�ṹ:  SOC_SCE_PROT_UNION */
#define SOC_SCE_PROT_ADDR(base)                       ((base) + (0x02F0))

/* �Ĵ���˵����testpointѡ���ź�
   λ����UNION�ṹ:  SOC_SCE_TP_MUX_UNION */
#define SOC_SCE_TP_MUX_ADDR(base)                     ((base) + (0x02F4))

/* �Ĵ���˵����SCE AXI��дͨ·�Ƿ�֧��cacheable�����ı�־
   λ����UNION�ṹ:  SOC_SCE_CACHE_CTRL_UNION */
#define SOC_SCE_CACHE_CTRL_ADDR(base)                 ((base) + (0x300))

/* �Ĵ���˵����CTRL_RX�Ѿ����յ���burst����
   λ����UNION�ṹ:  SOC_SCE_RX_RES_BURST_UNION */
#define SOC_SCE_RX_RES_BURST_ADDR(base)               ((base) + (0x304))

/* �Ĵ���˵����CTRL_RX�Ѿ����յ���word����
   λ����UNION�ṹ:  SOC_SCE_RX_RES_WORD_UNION */
#define SOC_SCE_RX_RES_WORD_ADDR(base)                ((base) + (0x308))

/* �Ĵ���˵����CTRL_TX��û�б����յ�burst����
   λ����UNION�ṹ:  SOC_SCE_TX_REMAIN_BURST_UNION */
#define SOC_SCE_TX_REMAIN_BURST_ADDR(base)            ((base) + (0x30C))

/* �Ĵ���˵����CTRL_TX��û�б����յ�word����
   λ����UNION�ṹ:  SOC_SCE_TX_REMAIN_WORD_UNION */
#define SOC_SCE_TX_REMAIN_WORD_ADDR(base)             ((base) + (0x310))

/* �Ĵ���˵����������ݳ���
   λ����UNION�ṹ:  SOC_SCE_AAD_LEN_UNION */
#define SOC_SCE_AAD_LEN_ADDR(base)                    ((base) + (0x0314))

/* �Ĵ���˵����T_Q���ݳ���
   λ����UNION�ṹ:  SOC_SCE_T_Q_LENTH_UNION */
#define SOC_SCE_T_Q_LENTH_ADDR(base)                  ((base) + (0x0318))

/* �Ĵ���˵����CCMУ������־
   λ����UNION�ṹ:  SOC_SCE_CCM_VER_FAIL_UNION */
#define SOC_SCE_CCM_VER_FAIL_ADDR(base)               ((base) + (0x031c))

/* �Ĵ���˵����CCMУ������־λclr�ź�
   λ����UNION�ṹ:  SOC_SCE_CCM_VER_FAIL_CLR_UNION */
#define SOC_SCE_CCM_VER_FAIL_CLR_ADDR(base)           ((base) + (0x0320))

/* �Ĵ���˵����XTS KEY1����ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_SCE_AES_KEY_PARITY_UNION */
#define SOC_SCE_AES_KEY_PARITY_ADDR(base)             ((base) + (0x0324))

/* �Ĵ���˵����XTS KEY2����ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_SCE_AES_KEY2_PARITY_UNION */
#define SOC_SCE_AES_KEY2_PARITY_ADDR(base)            ((base) + (0x0328))

/* �Ĵ���˵����KEY_REG_LOCK
   λ����UNION�ṹ:  SOC_SCE_KEY_REG_LOCK_UNION */
#define SOC_SCE_KEY_REG_LOCK_ADDR(base)               ((base) + (0x32c))

/* �Ĵ���˵����GCM��ʼֵ
   λ����UNION�ṹ:  SOC_SCE_gcm_counter0_UNION */
#define SOC_SCE_gcm_counter0_ADDR(base, n)            ((base) + (0x0340+(n)*4))

/* �Ĵ���˵����ccm_q
   λ����UNION�ṹ:  SOC_SCE_ccm_q_UNION */
#define SOC_SCE_ccm_q_ADDR(base, n)                   ((base) + (0x0380+(n)*4))

/* �Ĵ���˵����ccm_nonce
   λ����UNION�ṹ:  SOC_SCE_ccm_nonce_UNION */
#define SOC_SCE_ccm_nonce_ADDR(base, n)               ((base) + (0x03c0+(n)*4))

/* �Ĵ���˵����tweak_value��ʼֵ
   λ����UNION�ṹ:  SOC_SCE_tweak_value_UNION */
#define SOC_SCE_tweak_value_ADDR(base, n)             ((base) + (0x0400+(n)*4))

/* �Ĵ���˵����tweak_value��ʼֵ
   λ����UNION�ṹ:  SOC_SCE_xts_multi_data_UNION */
#define SOC_SCE_xts_multi_data_ADDR(base, n)          ((base) + (0x0440+(n)*4))

/* �Ĵ���˵����previous_ghash_digest
   λ����UNION�ṹ:  SOC_SCE_previous_ghash_digest_UNION */
#define SOC_SCE_previous_ghash_digest_ADDR(base, n)   ((base) + (0x0480+(n)*4))

/* �Ĵ���˵����aes_tag_out
   λ����UNION�ṹ:  SOC_SCE_aes_tag_out_UNION */
#define SOC_SCE_aes_tag_out_ADDR(base, n)             ((base) + (0x04c0+(n)*4))

/* �Ĵ���˵����ccm_tag_out_4ver
   λ����UNION�ṹ:  SOC_SCE_ccm_tag_out_4ver_UNION */
#define SOC_SCE_ccm_tag_out_4ver_ADDR(base, n)        ((base) + (0x0500+(n)*4))

/* �Ĵ���˵����AES_KEY1
   λ����UNION�ṹ:  SOC_SCE_AES_KEY1_UNION */
#define SOC_SCE_AES_KEY1_ADDR(base, n)                ((base) + (0x0540+(n)*4))

/* �Ĵ���˵����XTS KEY1����Կ����Ĵ���
   λ����UNION�ṹ:  SOC_SCE_AESKEY1_MASK_VALUE_UNION */
#define SOC_SCE_AESKEY1_MASK_VALUE_ADDR(base)         ((base) + (0x0580))

/* �Ĵ���˵����AES_KEY2
   λ����UNION�ṹ:  SOC_SCE_AES_KEY2_UNION */
#define SOC_SCE_AES_KEY2_ADDR(base, n)                ((base) + (0x05C0+(n)*4))

/* �Ĵ���˵����XTS KEY2����Կ����Ĵ���
   λ����UNION�ṹ:  SOC_SCE_AESKEY2_MASK_VALUE_UNION */
#define SOC_SCE_AESKEY2_MASK_VALUE_ADDR(base)         ((base) + (0x06a0))





/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/



/*****************************************************************************
  4 ��Ϣͷ����
*****************************************************************************/


/*****************************************************************************
  5 ��Ϣ����
*****************************************************************************/



/*****************************************************************************
  6 STRUCT����
*****************************************************************************/



/*****************************************************************************
  7 UNION����
*****************************************************************************/

/****************************************************************************
                     (1/1) reg_define
 ****************************************************************************/
/*****************************************************************************
 �ṹ��    : SOC_SCE_MODE_UNION
 �ṹ˵��  : MODE �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ӽ���IPѡ��,�ӽ��ܹ�����ʽ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_rx_dma_mode : 1;  /* bit[0]   : SCE���շ�������ʽ
                                                          0:CPU ��ʽ
                                                          1:MASTER��ʽ */
        unsigned int  reserved_0      : 3;  /* bit[1-3] :  */
        unsigned int  sce_ip_sel      : 4;  /* bit[4-7] : �ӽ���IPѡ��
                                                          4��h0:AES
                                                          4��h1:SM4
                                                          4��h2:DES
                                                          4��h4:SHA1
                                                          4��h5:MD5
                                                          4��h6:SHA256
                                                          4��h7:SM3
                                                          4��hc:SHA512 */
        unsigned int  sce_tx_dma_mode : 1;  /* bit[8]   : SCE���ͷ�������ʽ
                                                          0:CPU ��ʽ
                                                          1:MASTER��ʽ */
        unsigned int  reserved_1      : 23; /* bit[9-31]:  */
    } reg;
} SOC_SCE_MODE_UNION;
#endif
#define SOC_SCE_MODE_sce_rx_dma_mode_START  (0)
#define SOC_SCE_MODE_sce_rx_dma_mode_END    (0)
#define SOC_SCE_MODE_sce_ip_sel_START       (4)
#define SOC_SCE_MODE_sce_ip_sel_END         (7)
#define SOC_SCE_MODE_sce_tx_dma_mode_START  (8)
#define SOC_SCE_MODE_sce_tx_dma_mode_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_SCE_RX_DAT_LEN_UNION
 �ṹ˵��  : RX_DAT_LEN �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������շ������ݳ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_rx_dat_len : 32; /* bit[0-31]: ������շ������ݳ���
                                                         ���ֽ�Ϊ��λ��֧�ַ�ΧΪ1-10M�ֽ� */
    } reg;
} SOC_SCE_RX_DAT_LEN_UNION;
#endif
#define SOC_SCE_RX_DAT_LEN_sce_rx_dat_len_START  (0)
#define SOC_SCE_RX_DAT_LEN_sce_rx_dat_len_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CFG_UNION
 �ṹ˵��  : CFG �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x00000100�����:32
 �Ĵ���˵��: �����������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  lowpower_en       : 1;  /* bit[0]    : SM4�͹���ģʽʹ�ܡ�
                                                             1:�����͹���ģʽ
                                                             0:�������͹���ģʽ */
        unsigned int  reserved_0        : 3;  /* bit[1-3]  :  */
        unsigned int  sce_decrypt       : 1;  /* bit[4]    : �ӽ��ܱ�־��
                                                             1:��ʾ���ܣ�
                                                             0:��ʾ���� */
        unsigned int  reserved_1        : 3;  /* bit[5-7]  :  */
        unsigned int  sce_mode          : 4;  /* bit[8-11] : �ԳƼ�������Ĺ���ģʽ
                                                             0001:ECB;
                                                             0010:CBC
                                                             0100:CMAC 
                                                             0011:CBC MAC
                                                             0101:XTS
                                                             0111:CTR
                                                             1000��GCM�������ݵļ���ģʽ��
                                                             1001��GCM IV��ʼ���ļ���ģʽ��
                                                             1010��GMAC����ģʽ��
                                                             1011��GCM�ӽ�������ģʽ��
                                                             1100��CCM������ݵ�һ�������㣻
                                                             1101��CCM������ݵڶ��������㣻
                                                             1110��CCM��������
                                                             1111��CCM��������
                                                             �����Ƿ���
                                                             
                                                             ��sce�б���չΪ5bit��ֻ��ע�ϱߵ��������ɡ�
                                                             00001��ECBģʽ��
                                                             00010��CBCģʽ��
                                                             01000��CBC MACģʽ��
                                                             00100��CMACģʽ��
                                                             01111��CTRģʽ��
                                                             10000��GCM�������ݵļ���ģʽ��
                                                             10001��GCM IV��ʼ���ļ���ģʽ��
                                                             10010��GMAC����ģʽ��
                                                             10011��GCM�ӽ�������ģʽ��
                                                             10100��CCM������ݵ�һ�������㣻
                                                             10101��CCM������ݵڶ��������㣻
                                                             10110��CCM��������
                                                             10111��CCM��������
                                                             11000��XTS�ӽ�������ģʽ */
        unsigned int  sce_key_length    : 2;  /* bit[12-13]: ��Կ����ָʾ
                                                             00:128bit
                                                             01:192bit
                                                             10:256bit,
                                                             ��������ֵ�Ƿ�
                                                             ����AES,����IP�������ô˼Ĵ����� */
        unsigned int  reserved_2        : 2;  /* bit[14-15]: �ϱ��̶�Ϊ0 */
        unsigned int  mask_disable      : 1;  /* bit[16]   : ȥ����Ĵ���������debugģʽ����Ч
                                                             1:ȥ����
                                                             0:��ȥ���� */
        unsigned int  reserved_3        : 3;  /* bit[17-19]: �ϱ��̶�Ϊ0 */
        unsigned int  sce_dfa_en        : 1;  /* bit[20]   : DFAʹ�ܼĴ���
                                                             1:DFAʹ��
                                                             0:DFA��ʹ�� */
        unsigned int  reserved_4        : 3;  /* bit[21-23]: �ϱ��̶�Ϊ0 */
        unsigned int  tdes              : 1;  /* bit[24]   : DES/3DES����ѡ��
                                                             0:DES������
                                                             1:3DES���� */
        unsigned int  reserved_5        : 3;  /* bit[25-27]: �ϱ��̶�Ϊ0 */
        unsigned int  tx_big_little_end : 1;  /* bit[28]   : ���ͷ���������Դ�Ĵ�С�˱�־
                                                             0:�ⲿ����ΪС�ˣ��Ὣ��SCE�ͳ������ݽ���word���ֽ��򵹻���ת��Ϊ���ģʽ
                                                             1:�ⲿ����Ϊ��ˣ����Ὣ��SCE�ͳ������ݽ���word���ֽ��򵹻� */
        unsigned int  rx_big_little_end : 1;  /* bit[29]   : ���շ���������Դ�Ĵ�С�˱�־,Ĭ��С��
                                                             0:�ⲿ����ΪС�ˣ�����ͽ�SCE�����ݽ���word���ֽ��򵹻���ת��Ϊ���ģʽ
                                                             1:�ⲿ����Ϊ��ˣ������ͽ�SCE������word�ڽ����ֽ��򵹻� */
        unsigned int  sce_padding_sel   : 1;  /* bit[30]   : AES\DES\SM4��padding��ʽѡ��Ĭ��Ϊ00
                                                             1:padding 00
                                                             0:padding 80
                                                             ����ֵ�Ƿ� */
        unsigned int  reserved_6        : 1;  /* bit[31]   : �ϱ��̶�Ϊ0 */
    } reg;
} SOC_SCE_CFG_UNION;
#endif
#define SOC_SCE_CFG_lowpower_en_START        (0)
#define SOC_SCE_CFG_lowpower_en_END          (0)
#define SOC_SCE_CFG_sce_decrypt_START        (4)
#define SOC_SCE_CFG_sce_decrypt_END          (4)
#define SOC_SCE_CFG_sce_mode_START           (8)
#define SOC_SCE_CFG_sce_mode_END             (11)
#define SOC_SCE_CFG_sce_key_length_START     (12)
#define SOC_SCE_CFG_sce_key_length_END       (13)
#define SOC_SCE_CFG_mask_disable_START       (16)
#define SOC_SCE_CFG_mask_disable_END         (16)
#define SOC_SCE_CFG_sce_dfa_en_START         (20)
#define SOC_SCE_CFG_sce_dfa_en_END           (20)
#define SOC_SCE_CFG_tdes_START               (24)
#define SOC_SCE_CFG_tdes_END                 (24)
#define SOC_SCE_CFG_tx_big_little_end_START  (28)
#define SOC_SCE_CFG_tx_big_little_end_END    (28)
#define SOC_SCE_CFG_rx_big_little_end_START  (29)
#define SOC_SCE_CFG_rx_big_little_end_END    (29)
#define SOC_SCE_CFG_sce_padding_sel_START    (30)
#define SOC_SCE_CFG_sce_padding_sel_END      (30)


/*****************************************************************************
 �ṹ��    : SOC_SCE_BUSY_DONE_UNION
 �ṹ˵��  : BUSY_DONE �Ĵ����ṹ���塣��ַƫ����:0x000C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0   : 4;  /* bit[0-3]  :  */
        unsigned int  sce_busy_reg : 1;  /* bit[4]    : sce æ�ź�
                                                        1:��ʾbusy */
        unsigned int  reserved_1   : 3;  /* bit[5-7]  :  */
        unsigned int  sce_done_reg : 1;  /* bit[8]    : ��������ź�
                                                        1:��ʾ��� */
        unsigned int  reserved_2   : 3;  /* bit[9-11] :  */
        unsigned int  ctrl_rx_busy : 1;  /* bit[12]   : CTRL_RXģ��busy״̬�ı�־
                                                        1:��ʾbusy */
        unsigned int  reserved_3   : 3;  /* bit[13-15]:  */
        unsigned int  ctrl_tx_busy : 1;  /* bit[16]   : CTRL_TXģ��busy״̬�ı�־
                                                        1:��ʾbusy */
        unsigned int  reserved_4   : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_BUSY_DONE_UNION;
#endif
#define SOC_SCE_BUSY_DONE_sce_busy_reg_START  (4)
#define SOC_SCE_BUSY_DONE_sce_busy_reg_END    (4)
#define SOC_SCE_BUSY_DONE_sce_done_reg_START  (8)
#define SOC_SCE_BUSY_DONE_sce_done_reg_END    (8)
#define SOC_SCE_BUSY_DONE_ctrl_rx_busy_START  (12)
#define SOC_SCE_BUSY_DONE_ctrl_rx_busy_END    (12)
#define SOC_SCE_BUSY_DONE_ctrl_tx_busy_START  (16)
#define SOC_SCE_BUSY_DONE_ctrl_tx_busy_END    (16)


/*****************************************************************************
 �ṹ��    : SOC_SCE_FIFO_LINE_UNION
 �ṹ˵��  : FIFO_LINE �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x00680600�����:32
 �Ĵ���˵��: FIFOˮ���ϱ�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0     : 4;  /* bit[0-3]  : reserved */
        unsigned int  reserved_1     : 4;  /* bit[4-7]  : reserved */
        unsigned int  fifo_rx_afull  : 1;  /* bit[8]    : fifo_rx_afull */
        unsigned int  fifo_rx_aempty : 1;  /* bit[9]    : fifo_rx_aempty */
        unsigned int  fifo_rx_empty  : 1;  /* bit[10]   : fifo_rx_empty */
        unsigned int  fifo_rx_full   : 1;  /* bit[11]   : fifo_rx_full */
        unsigned int  fifo_rx_cnt    : 8;  /* bit[12-19]: fifo_rx_cnt��ʾ�ж��ٿռ����д */
        unsigned int  fifo_tx_afull  : 1;  /* bit[20]   : fifo_tx_afull */
        unsigned int  fifo_tx_aempty : 1;  /* bit[21]   : fifo_tx_aempty */
        unsigned int  fifo_tx_empty  : 1;  /* bit[22]   : fifo_tx_empty */
        unsigned int  fifo_tx_full   : 1;  /* bit[23]   : fifo_tx_full */
        unsigned int  fifo_tx_cnt    : 8;  /* bit[24-31]: fifo_tx_cnt */
    } reg;
} SOC_SCE_FIFO_LINE_UNION;
#endif
#define SOC_SCE_FIFO_LINE_fifo_rx_afull_START   (8)
#define SOC_SCE_FIFO_LINE_fifo_rx_afull_END     (8)
#define SOC_SCE_FIFO_LINE_fifo_rx_aempty_START  (9)
#define SOC_SCE_FIFO_LINE_fifo_rx_aempty_END    (9)
#define SOC_SCE_FIFO_LINE_fifo_rx_empty_START   (10)
#define SOC_SCE_FIFO_LINE_fifo_rx_empty_END     (10)
#define SOC_SCE_FIFO_LINE_fifo_rx_full_START    (11)
#define SOC_SCE_FIFO_LINE_fifo_rx_full_END      (11)
#define SOC_SCE_FIFO_LINE_fifo_rx_cnt_START     (12)
#define SOC_SCE_FIFO_LINE_fifo_rx_cnt_END       (19)
#define SOC_SCE_FIFO_LINE_fifo_tx_afull_START   (20)
#define SOC_SCE_FIFO_LINE_fifo_tx_afull_END     (20)
#define SOC_SCE_FIFO_LINE_fifo_tx_aempty_START  (21)
#define SOC_SCE_FIFO_LINE_fifo_tx_aempty_END    (21)
#define SOC_SCE_FIFO_LINE_fifo_tx_empty_START   (22)
#define SOC_SCE_FIFO_LINE_fifo_tx_empty_END     (22)
#define SOC_SCE_FIFO_LINE_fifo_tx_full_START    (23)
#define SOC_SCE_FIFO_LINE_fifo_tx_full_END      (23)
#define SOC_SCE_FIFO_LINE_fifo_tx_cnt_START     (24)
#define SOC_SCE_FIFO_LINE_fifo_tx_cnt_END       (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_STR_RUN_UNION
 �ṹ˵��  : STR_RUN �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ӽ������濪ʼ��־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_run  : 1;  /* bit[0]   : ���鿪ʼ����ı�־
                                                   1:��ʼ������� */
        unsigned int  reserved_0: 3;  /* bit[1-3] :  */
        unsigned int  sce_str  : 1;  /* bit[4]   : ��ʼ�������ò�����־
                                                   1:��ʼ�������ò�����־ */
        unsigned int  reserved_1: 3;  /* bit[5-7] :  */
        unsigned int  reserved_2: 24; /* bit[8-31]:  */
    } reg;
} SOC_SCE_STR_RUN_UNION;
#endif
#define SOC_SCE_STR_RUN_sce_run_START   (0)
#define SOC_SCE_STR_RUN_sce_run_END     (0)
#define SOC_SCE_STR_RUN_sce_str_START   (4)
#define SOC_SCE_STR_RUN_sce_str_END     (4)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ALARM_UNION
 �ṹ˵��  : ALARM �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ԳƼӽ��������ԭʼalarm�źţ�����ǰ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alarm         : 4;  /* bit[0-3]  : aes_alarm
                                                             ����bitΪ1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  sm4_alarm         : 4;  /* bit[4-7]  : sm4_alarm
                                                             ����bitΪ1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  des_alarm         : 4;  /* bit[8-11] : des_alarm�ź�
                                                             ����bitΪ1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  sce_alarm         : 1;  /* bit[12]   : sce���������alarm�ź�
                                                             1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  reg_check_alarm   : 1;  /* bit[13]   : �Ĵ����Ϸ��Լ�������alarm�ź�
                                                             1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  reg_access_alarm  : 1;  /* bit[14]   : LOCK���д�Ĵ���������alarm�ź�
                                                             1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  rx_response_alarm : 1;  /* bit[15]   : CTRL_RXģ��response�Ϸ��Լ�������alarm�ź�
                                                             1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  tx_response_alarm : 1;  /* bit[16]   : CTRL_TXģ��response�Ϸ��Լ�������alarm�ź�
                                                             1:��ʾ��alarm
                                                             0:û��alarm */
        unsigned int  reserved          : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_ALARM_UNION;
#endif
#define SOC_SCE_ALARM_aes_alarm_START          (0)
#define SOC_SCE_ALARM_aes_alarm_END            (3)
#define SOC_SCE_ALARM_sm4_alarm_START          (4)
#define SOC_SCE_ALARM_sm4_alarm_END            (7)
#define SOC_SCE_ALARM_des_alarm_START          (8)
#define SOC_SCE_ALARM_des_alarm_END            (11)
#define SOC_SCE_ALARM_sce_alarm_START          (12)
#define SOC_SCE_ALARM_sce_alarm_END            (12)
#define SOC_SCE_ALARM_reg_check_alarm_START    (13)
#define SOC_SCE_ALARM_reg_check_alarm_END      (13)
#define SOC_SCE_ALARM_reg_access_alarm_START   (14)
#define SOC_SCE_ALARM_reg_access_alarm_END     (14)
#define SOC_SCE_ALARM_rx_response_alarm_START  (15)
#define SOC_SCE_ALARM_rx_response_alarm_END    (15)
#define SOC_SCE_ALARM_tx_response_alarm_START  (16)
#define SOC_SCE_ALARM_tx_response_alarm_END    (16)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ALARM_MASK_EN_UNION
 �ṹ˵��  : ALARM_MASK_EN �Ĵ����ṹ���塣��ַƫ����:0x001C����ֵ:0x55555555�����:32
 �Ĵ���˵��: �ԳƼӽ�������alarm ����ʹ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_mask_en        : 4;  /* bit[0-3]  : aes_alarm�����ź�
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  sm4_alaram_mask_en        : 4;  /* bit[4-7]  : sm4_alarm�����ź�
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  des_alaram_mask_en        : 4;  /* bit[8-11] : des_alarm �����ź�
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  alarm_mask_en             : 4;  /* bit[12-15]: ֻ��sce����ؼ��źŲ�����alarm ����,Ĭ������
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  reg_check_alarm_mask_en   : 4;  /* bit[16-19]: �Ĵ����Ϸ��Լ�������alarm�ź����Σ�Ĭ������
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  reg_access_alarm_mask_en  : 4;  /* bit[20-23]: LOCK���д�Ĵ���������alarm�ź����Σ�Ĭ������
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  rx_response_alarm_mask_en : 4;  /* bit[24-27]: CTRL_RXģ��response�Ϸ��Լ�������alarm�ź����Σ�Ĭ�ϲ�����
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
        unsigned int  tx_response_alarm_mask_en : 4;  /* bit[28-31]: CTRL_TXģ��response�Ϸ��Լ�������alarm�ź����Σ�Ĭ�ϲ�����
                                                                     0x5:��alarm��������
                                                                     0xa:����alarm��������
                                                                     ��������ֵ�Ƿ� */
    } reg;
} SOC_SCE_ALARM_MASK_EN_UNION;
#endif
#define SOC_SCE_ALARM_MASK_EN_aes_alaram_mask_en_START         (0)
#define SOC_SCE_ALARM_MASK_EN_aes_alaram_mask_en_END           (3)
#define SOC_SCE_ALARM_MASK_EN_sm4_alaram_mask_en_START         (4)
#define SOC_SCE_ALARM_MASK_EN_sm4_alaram_mask_en_END           (7)
#define SOC_SCE_ALARM_MASK_EN_des_alaram_mask_en_START         (8)
#define SOC_SCE_ALARM_MASK_EN_des_alaram_mask_en_END           (11)
#define SOC_SCE_ALARM_MASK_EN_alarm_mask_en_START              (12)
#define SOC_SCE_ALARM_MASK_EN_alarm_mask_en_END                (15)
#define SOC_SCE_ALARM_MASK_EN_reg_check_alarm_mask_en_START    (16)
#define SOC_SCE_ALARM_MASK_EN_reg_check_alarm_mask_en_END      (19)
#define SOC_SCE_ALARM_MASK_EN_reg_access_alarm_mask_en_START   (20)
#define SOC_SCE_ALARM_MASK_EN_reg_access_alarm_mask_en_END     (23)
#define SOC_SCE_ALARM_MASK_EN_rx_response_alarm_mask_en_START  (24)
#define SOC_SCE_ALARM_MASK_EN_rx_response_alarm_mask_en_END    (27)
#define SOC_SCE_ALARM_MASK_EN_tx_response_alarm_mask_en_START  (28)
#define SOC_SCE_ALARM_MASK_EN_tx_response_alarm_mask_en_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ALARM_CLR_UNION
 �ṹ˵��  : ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x0020����ֵ:0xAAAAAAAA�����:32
 �Ĵ���˵��: �ԳƼӽ�������alarm�����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_clr        : 4;  /* bit[0-3]  : aes_alarm�����ź�
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  sm4_alaram_clr        : 4;  /* bit[4-7]  : sm4_alarm�����ź�
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  des_alaram_clr        : 4;  /* bit[8-11] : des_alarm �����ź�
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  alaram_clr            : 4;  /* bit[12-15]: ֻ��sce�ؼ��źŲ�����alarm ����
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  reg_check_alarm_clr   : 4;  /* bit[16-19]: �Ĵ����Ϸ��Լ�������alarm�ź�����
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  reg_access_alarm_clr  : 4;  /* bit[20-23]: LOCK���д�Ĵ���������alarm�ź�����
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  rx_response_alarm_clr : 4;  /* bit[24-27]: CTRL_RXģ��response�Ϸ��Լ�������alarm�ź�����
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
        unsigned int  tx_response_alarm_clr : 4;  /* bit[28-31]: CTRL_TXģ��response�Ϸ��Լ�������alarm�ź�����
                                                                 0x5:��alarm��������
                                                                 0xa:����alarm��������
                                                                 ��������ֵ�Ƿ� */
    } reg;
} SOC_SCE_ALARM_CLR_UNION;
#endif
#define SOC_SCE_ALARM_CLR_aes_alaram_clr_START         (0)
#define SOC_SCE_ALARM_CLR_aes_alaram_clr_END           (3)
#define SOC_SCE_ALARM_CLR_sm4_alaram_clr_START         (4)
#define SOC_SCE_ALARM_CLR_sm4_alaram_clr_END           (7)
#define SOC_SCE_ALARM_CLR_des_alaram_clr_START         (8)
#define SOC_SCE_ALARM_CLR_des_alaram_clr_END           (11)
#define SOC_SCE_ALARM_CLR_alaram_clr_START             (12)
#define SOC_SCE_ALARM_CLR_alaram_clr_END               (15)
#define SOC_SCE_ALARM_CLR_reg_check_alarm_clr_START    (16)
#define SOC_SCE_ALARM_CLR_reg_check_alarm_clr_END      (19)
#define SOC_SCE_ALARM_CLR_reg_access_alarm_clr_START   (20)
#define SOC_SCE_ALARM_CLR_reg_access_alarm_clr_END     (23)
#define SOC_SCE_ALARM_CLR_rx_response_alarm_clr_START  (24)
#define SOC_SCE_ALARM_CLR_rx_response_alarm_clr_END    (27)
#define SOC_SCE_ALARM_CLR_tx_response_alarm_clr_START  (28)
#define SOC_SCE_ALARM_CLR_tx_response_alarm_clr_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ALARM_MASK_UNION
 �ṹ˵��  : ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x0024����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ԳƼӽ��������alarm�źţ����κ�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_mask        : 4;  /* bit[0-3]  : aes_alarm
                                                                  ����bitΪ1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  sm4_alaram_mask        : 4;  /* bit[4-7]  : sm4_alarm
                                                                  ����bitΪ1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  des_alaram_mask        : 4;  /* bit[8-11] : des_alarm�ź�
                                                                  ����bitΪ1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  sce_alarm_mask         : 1;  /* bit[12]   : sce���������alarm�ź�
                                                                  1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  reg_check_alarm_mask   : 1;  /* bit[13]   : �Ĵ����Ϸ��Լ�������alarm�ź�
                                                                  1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  reg_access_alarm_mask  : 1;  /* bit[14]   : LOCK���д�Ĵ���������alarm�ź�
                                                                  1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  rx_response_alarm_mask : 1;  /* bit[15]   : CTRL_RXģ��response�Ϸ��Լ�������alarm�ź�
                                                                  1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  tx_response_alarm_mask : 1;  /* bit[16]   : CTRL_TXģ��response�Ϸ��Լ�������alarm�ź�
                                                                  1:��ʾ��alarm
                                                                  0:û��alarm */
        unsigned int  reserved               : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_ALARM_MASK_UNION;
#endif
#define SOC_SCE_ALARM_MASK_aes_alaram_mask_START         (0)
#define SOC_SCE_ALARM_MASK_aes_alaram_mask_END           (3)
#define SOC_SCE_ALARM_MASK_sm4_alaram_mask_START         (4)
#define SOC_SCE_ALARM_MASK_sm4_alaram_mask_END           (7)
#define SOC_SCE_ALARM_MASK_des_alaram_mask_START         (8)
#define SOC_SCE_ALARM_MASK_des_alaram_mask_END           (11)
#define SOC_SCE_ALARM_MASK_sce_alarm_mask_START          (12)
#define SOC_SCE_ALARM_MASK_sce_alarm_mask_END            (12)
#define SOC_SCE_ALARM_MASK_reg_check_alarm_mask_START    (13)
#define SOC_SCE_ALARM_MASK_reg_check_alarm_mask_END      (13)
#define SOC_SCE_ALARM_MASK_reg_access_alarm_mask_START   (14)
#define SOC_SCE_ALARM_MASK_reg_access_alarm_mask_END     (14)
#define SOC_SCE_ALARM_MASK_rx_response_alarm_mask_START  (15)
#define SOC_SCE_ALARM_MASK_rx_response_alarm_mask_END    (15)
#define SOC_SCE_ALARM_MASK_tx_response_alarm_mask_START  (16)
#define SOC_SCE_ALARM_MASK_tx_response_alarm_mask_END    (16)


/*****************************************************************************
 �ṹ��    : SOC_SCE_TX_DAT_LEN_UNION
 �ṹ˵��  : TX_DAT_LEN �Ĵ����ṹ���塣��ַƫ����:0x0030����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���淢�ͷ������ݳ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_tx_dat_len : 32; /* bit[0-31]: ���淢�ͷ������ݳ���
                                                         ���ֽ�Ϊ��λ��֧�ַ�ΧΪ1-10M�ֽ� */
    } reg;
} SOC_SCE_TX_DAT_LEN_UNION;
#endif
#define SOC_SCE_TX_DAT_LEN_sce_tx_dat_len_START  (0)
#define SOC_SCE_TX_DAT_LEN_sce_tx_dat_len_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_REG_LOCK_UNION
 �ṹ˵��  : REG_LOCK �Ĵ����ṹ���塣��ַƫ����:0x0034����ֵ:0x00000005�����:32
 �Ĵ���˵��: SCE�Ĵ��������ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_reg_lock : 4;  /* bit[0-3] : �Ĵ����Ķ�д������Ĭ��Ϊ0x5
                                                       0x5���������κμĴ��������ɶ�д
                                                       0xa��δ�������Ĵ����ɶ�д
                                                       ��������ֵ�Ƿ� */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_REG_LOCK_UNION;
#endif
#define SOC_SCE_REG_LOCK_sce_reg_lock_START  (0)
#define SOC_SCE_REG_LOCK_sce_reg_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_DIN_UNION
 �ṹ˵��  : DIN �Ĵ����ṹ���塣��ַƫ����:0x0040+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������յ�һ�����ݷ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_din : 32; /* bit[0-31]: ������յ�һ�����ݷ���,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-15 */
    } reg;
} SOC_SCE_DIN_UNION;
#endif
#define SOC_SCE_DIN_sce_din_START  (0)
#define SOC_SCE_DIN_sce_din_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_IVIN_UNION
 �ṹ˵��  : IVIN �Ĵ����ṹ���塣��ַƫ����:0x0080+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������յ�IV IN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_ivin : 32; /* bit[0-31]: ������յ�nV nN��n=0ʱ����ӦnV�ĸ�32λ,n�ķ�Χ0-15 */
    } reg;
} SOC_SCE_IVIN_UNION;
#endif
#define SOC_SCE_IVIN_sce_ivin_START  (0)
#define SOC_SCE_IVIN_sce_ivin_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_DOUT_UNION
 �ṹ˵��  : DOUT �Ĵ����ṹ���塣��ַƫ����:0x00C0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����������һ�����ݷ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_dout : 32; /* bit[0-31]: ����������һ�����ݷ��飬n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-15 */
    } reg;
} SOC_SCE_DOUT_UNION;
#endif
#define SOC_SCE_DOUT_sce_dout_START  (0)
#define SOC_SCE_DOUT_sce_dout_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_IVOUT_UNION
 �ṹ˵��  : IVOUT �Ĵ����ṹ���塣��ַƫ����:0x0100+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����������IV OUT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_ivout : 32; /* bit[0-31]: ����������nV OUT,n=0ʱ����ӦnV�ĸ�32λ,n�ķ�Χ0-15 */
    } reg;
} SOC_SCE_IVOUT_UNION;
#endif
#define SOC_SCE_IVOUT_sce_ivout_START  (0)
#define SOC_SCE_IVOUT_sce_ivout_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_POWER_DISTURB_EN_UNION
 �ṹ˵��  : POWER_DISTURB_EN �Ĵ����ṹ���塣��ַƫ����:0x0140����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ���ļ�ʹ�ܱ�־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_en : 4;  /* bit[0-3] : �Ƿ�򿪹��ļ���
                                                           0x5:Ĭ��ʹ��MD5���й��ļ���
                                                           0xa:��ʹ��MD5���й��ļ���
                                                           ��������ֵ�Ƿ� */
        unsigned int  reserved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_POWER_DISTURB_EN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_EN_power_disturb_en_START  (0)
#define SOC_SCE_POWER_DISTURB_EN_power_disturb_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_POWER_DISTURB_RUN_UNION
 �ṹ˵��  : POWER_DISTURB_RUN �Ĵ����ṹ���塣��ַƫ����:0x0144����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���ļ���������־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_run : 1;  /* bit[0]   : ���ļ���������־
                                                            1:�������ļ���
                                                            0:�رչ��ļ��Ź��� */
        unsigned int  reserved          : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_POWER_DISTURB_RUN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_RUN_power_disturb_run_START  (0)
#define SOC_SCE_POWER_DISTURB_RUN_power_disturb_run_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SCE_POWER_DISTURB_DIN_UNION
 �ṹ˵��  : POWER_DISTURB_DIN �Ĵ����ṹ���塣��ַƫ����:0x0180+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����MD5���й��ļ���ʱ�ĳ�ʼ����ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_din : 32; /* bit[0-31]: ����MD5���й��ļ���ʱ�ĳ�ʼ����ֵ,n=0ʱ����Ӧdnn�ĸ�32λ��n�ķ�Χ0-15������MD5��PADDnNG��ʽ�����ݹ̶�ΪС�����룬paddnng��ĳ��ȴ�����룬�ҳ��ȴ���ڵ����ڶ���word�ϡ� */
    } reg;
} SOC_SCE_POWER_DISTURB_DIN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_DIN_power_disturb_din_START  (0)
#define SOC_SCE_POWER_DISTURB_DIN_power_disturb_din_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_REDROUND_EN_UNION
 �ṹ˵��  : REDROUND_EN �Ĵ����ṹ���塣��ַƫ����:0x01C0����ֵ:0x0000000A�����:32
 �Ĵ���˵��: αroundʹ���ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_redround_en : 4;  /* bit[0-3] : αroundʹ�ܣ�Ĭ�ϲ�ʹ��
                                                          0x5��ʹ��αround
                                                          0xa����ʹ��αround
                                                          ��������ֵ�Ƿ� */
        unsigned int  reserved        : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_REDROUND_EN_UNION;
#endif
#define SOC_SCE_REDROUND_EN_sce_redround_en_START  (0)
#define SOC_SCE_REDROUND_EN_sce_redround_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_REDROUND_NUM_UNION
 �ṹ˵��  : REDROUND_NUM �Ĵ����ṹ���塣��ַƫ����:0x01C4����ֵ:0x00000007�����:32
 �Ĵ���˵��: αround����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_redround_num : 3;  /* bit[0-2] : αround������Ĭ��7��
                                                           0x3:3��
                                                           0x7:7��
                                                           ��������ֵ�Ƿ��� */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_SCE_REDROUND_NUM_UNION;
#endif
#define SOC_SCE_REDROUND_NUM_sce_redround_num_START  (0)
#define SOC_SCE_REDROUND_NUM_sce_redround_num_END    (2)


/*****************************************************************************
 �ṹ��    : SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION
 �ṹ˵��  : RNG_ACTIVE_CHECK_EN �Ĵ����ṹ���塣��ַƫ����:0x01C8����ֵ:0x0000000A�����:32
 �Ĵ���˵��: SM4����������Ƿ�仯���ʹ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rng_active_check_en : 4;  /* bit[0-3] : SM4�����Ƿ�仯����źţ�Ĭ�ϲ�ʹ��
                                                              0x5:ʹ��
                                                              0xa:��ʹ��
                                                              ��������ֵ�Ƿ� */
        unsigned int  reserved            : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION;
#endif
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_rng_active_check_en_START  (0)
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_rng_active_check_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_HASH_PADDING_EN_UNION
 �ṹ˵��  : HASH_PADDING_EN �Ĵ����ṹ���塣��ַƫ����:0x01CC����ֵ:0x00000001�����:32
 �Ĵ���˵��: HASH�ֶ�ʱ�Ƿ�padding�ı�־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hash_padding_en : 1;  /* bit[0]   : HASH�ֶ�ʱ�Ƿ�padding�ı�־
                                                          0:NOT PADDING
                                                          1:PADDING */
        unsigned int  reserved        : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_HASH_PADDING_EN_UNION;
#endif
#define SOC_SCE_HASH_PADDING_EN_hash_padding_en_START  (0)
#define SOC_SCE_HASH_PADDING_EN_hash_padding_en_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SCE_EFUSEC_DBG_UNION
 �ṹ˵��  : EFUSEC_DBG �Ĵ����ṹ���塣��ַƫ����:0x01D0����ֵ:0x00000AAA�����:32
 �Ĵ���˵��: EFUSEC�����SCE���ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  debug_disable : 4;  /* bit[0-3]  : Debug disable
                                                         0xA:����ģʽ
                                                         0x5:�ǵ���ģʽ
                                                         ����ֵ�Ƿ� */
        unsigned int  sm4_disable   : 4;  /* bit[4-7]  : SM4 disable
                                                         0xA:SM4������
                                                         0x5:SM4����
                                                         ����ֵ�Ƿ� */
        unsigned int  sm3_disable   : 4;  /* bit[8-11] : SM3 disable
                                                         0xA:SM3������
                                                         0x5:SM3����
                                                         ����ֵ�Ƿ� */
        unsigned int  reserved      : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_EFUSEC_DBG_UNION;
#endif
#define SOC_SCE_EFUSEC_DBG_debug_disable_START  (0)
#define SOC_SCE_EFUSEC_DBG_debug_disable_END    (3)
#define SOC_SCE_EFUSEC_DBG_sm4_disable_START    (4)
#define SOC_SCE_EFUSEC_DBG_sm4_disable_END      (7)
#define SOC_SCE_EFUSEC_DBG_sm3_disable_START    (8)
#define SOC_SCE_EFUSEC_DBG_sm3_disable_END      (11)


/*****************************************************************************
 �ṹ��    : SOC_SCE_IP_EN_UNION
 �ṹ˵��  : IP_EN �Ĵ����ṹ���塣��ַƫ����:0x01D4����ֵ:0x00000AAA�����:32
 �Ĵ���˵��: �Գ�IPʹ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_en   : 4;  /* bit[0-3]  : AESʹ�ܣ������ڼ���뱣��0x5��������ʱ����0xA���͹���
                                                    0xA:��ʹ��
                                                    0x5:ʹ��
                                                    ����ֵ�Ƿ� */
        unsigned int  sm4_en   : 4;  /* bit[4-7]  : SM4ʹ�ܣ������ڼ���뱣��0x5��������ʱ����0xA���͹���
                                                    0xA:��ʹ��
                                                    0x5:ʹ��
                                                    ����ֵ�Ƿ� */
        unsigned int  des_en   : 4;  /* bit[8-11] : DESʹ�ܣ������ڼ���뱣��0x5��������ʱ����0xA���͹���
                                                    0xA:��ʹ��
                                                    0x5:ʹ��
                                                    ����ֵ�Ƿ� */
        unsigned int  reserved : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_IP_EN_UNION;
#endif
#define SOC_SCE_IP_EN_aes_en_START    (0)
#define SOC_SCE_IP_EN_aes_en_END      (3)
#define SOC_SCE_IP_EN_sm4_en_START    (4)
#define SOC_SCE_IP_EN_sm4_en_END      (7)
#define SOC_SCE_IP_EN_des_en_START    (8)
#define SOC_SCE_IP_EN_des_en_END      (11)


/*****************************************************************************
 �ṹ��    : SOC_SCE_HASH_DATA_LENTH_ALL_UNION
 �ṹ˵��  : HASH_DATA_LENTH_ALL �Ĵ����ṹ���塣��ַƫ����:0x0200����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����hash������ܵ����ݳ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hash_data_lenth_all : 32; /* bit[0-31]: ����hash������ܵ����ݳ��ȣ���λΪ�ֽڡ����ȷ�Χ1-10M BYTE */
    } reg;
} SOC_SCE_HASH_DATA_LENTH_ALL_UNION;
#endif
#define SOC_SCE_HASH_DATA_LENTH_ALL_hash_data_lenth_all_START  (0)
#define SOC_SCE_HASH_DATA_LENTH_ALL_hash_data_lenth_all_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CNTIN_UNION
 �ṹ˵��  : CNTIN �Ĵ����ṹ���塣��ַƫ����:0x0240+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRģʽ������յļ������ĳ�ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_cntin : 32; /* bit[0-31]: CTRģʽʱ���õ�cnt��ʼֵ,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_CNTIN_UNION;
#endif
#define SOC_SCE_CNTIN_sce_cntin_START  (0)
#define SOC_SCE_CNTIN_sce_cntin_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CNTOUT_UNION
 �ṹ˵��  : CNTOUT �Ĵ����ṹ���塣��ַƫ����:0x0280+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRģʽ��������ļ������ĳ�ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_cntout : 32; /* bit[0-31]: CTRģʽʱ�����cnt��ʼֵ,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_CNTOUT_UNION;
#endif
#define SOC_SCE_CNTOUT_sce_cntout_START  (0)
#define SOC_SCE_CNTOUT_sce_cntout_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_SRC_ADDR_UNION
 �ṹ˵��  : SRC_ADDR �Ĵ����ṹ���塣��ַƫ����:0x02C0����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ȡ���ݵ�Դ��ַ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_src_addr_low : 32; /* bit[0-31]: ����ȡ���ݵ�Դ��ַ */
    } reg;
} SOC_SCE_SRC_ADDR_UNION;
#endif
#define SOC_SCE_SRC_ADDR_sce_src_addr_low_START  (0)
#define SOC_SCE_SRC_ADDR_sce_src_addr_low_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_DES_ADDR_UNION
 �ṹ˵��  : DES_ADDR �Ĵ����ṹ���塣��ַƫ����:0x02C4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���������ݵ�Ŀ�ĵ�ַ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_des_addr_low : 32; /* bit[0-31]: ���������ݵ�Ŀ�ĵ�ַ */
    } reg;
} SOC_SCE_DES_ADDR_UNION;
#endif
#define SOC_SCE_DES_ADDR_sce_des_addr_low_START  (0)
#define SOC_SCE_DES_ADDR_sce_des_addr_low_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_IV_BYPASS_UNION
 �ṹ˵��  : IV_BYPASS �Ĵ����ṹ���塣��ַƫ����:0x02CC����ֵ:0x000000AA�����:32
 �Ĵ���˵��: ���ݿ�ָʾ�ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  plaintext_en      : 4;  /* bit[0-3]  : ������ָʾ�ź�
                                                             0xA:����
                                                             0x5:���� */
        unsigned int  iv_sel            : 4;  /* bit[4-7]  : ��ǰ���ݿ��iv��ѡ��������õĻ���Ӳ��ԭ�����ɵ�
                                                             0xA:ʹ��������õ�
                                                             0x5:Ӳ��ԭ�����ɵ� */
        unsigned int  sce_src_addr_high : 5;  /* bit[8-12] : Դ��ַ�ĸ�λ */
        unsigned int  sce_des_addr_high : 5;  /* bit[13-17]: Ŀ�ĵ�ַ�ĸ�λ */
        unsigned int  reserved          : 14; /* bit[18-31]:  */
    } reg;
} SOC_SCE_IV_BYPASS_UNION;
#endif
#define SOC_SCE_IV_BYPASS_plaintext_en_START       (0)
#define SOC_SCE_IV_BYPASS_plaintext_en_END         (3)
#define SOC_SCE_IV_BYPASS_iv_sel_START             (4)
#define SOC_SCE_IV_BYPASS_iv_sel_END               (7)
#define SOC_SCE_IV_BYPASS_sce_src_addr_high_START  (8)
#define SOC_SCE_IV_BYPASS_sce_src_addr_high_END    (12)
#define SOC_SCE_IV_BYPASS_sce_des_addr_high_START  (13)
#define SOC_SCE_IV_BYPASS_sce_des_addr_high_END    (17)


/*****************************************************************************
 �ṹ��    : SOC_SCE_INT_SCE_MASK_EN_UNION
 �ṹ˵��  : INT_SCE_MASK_EN �Ĵ����ṹ���塣��ַƫ����:0x02D0����ֵ:0x00000005�����:32
 �Ĵ���˵��: �ж����μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_mask_en : 4;  /* bit[0-3]  : 0x5�����θ��ж�Դ
                                                           0xA�������θ��ж�Դ */
        unsigned int  reserved_0      : 12; /* bit[4-15] : ���� */
        unsigned int  reserved_1      : 16; /* bit[16-31]: ���� */
    } reg;
} SOC_SCE_INT_SCE_MASK_EN_UNION;
#endif
#define SOC_SCE_INT_SCE_MASK_EN_sce_int_mask_en_START  (0)
#define SOC_SCE_INT_SCE_MASK_EN_sce_int_mask_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_INT_SCE_MASK_UNION
 �ṹ˵��  : INT_SCE_MASK �Ĵ����ṹ���塣��ַƫ����:0x02D4����ֵ:0x0000000A�����:32
 �Ĵ���˵��: �ж�״̬�Ĵ���(���κ��ϱ���״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_mask : 4;  /* bit[0-3]  : mask��������ж� ״̬�Ĵ���
                                                        0x5������ж���Ч����ʾ�������
                                                        0xA������ж���Ч���������߼����ڴ���Ҳ�п����Ǵ�����ɣ������жϱ�mask������δ�������� */
        unsigned int  reserved_0   : 12; /* bit[4-15] : ���� */
        unsigned int  reserved_1   : 16; /* bit[16-31]: ���� */
    } reg;
} SOC_SCE_INT_SCE_MASK_UNION;
#endif
#define SOC_SCE_INT_SCE_MASK_sce_int_mask_START  (0)
#define SOC_SCE_INT_SCE_MASK_sce_int_mask_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_INT_SCE_UNION
 �ṹ˵��  : INT_SCE �Ĵ����ṹ���塣��ַƫ����:0x02D8����ֵ:0x0000000A�����:32
 �Ĵ���˵��: �ж�����ǰ״̬�Ĵ���(ʵ��״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int  : 4;  /* bit[0-3]  : maskǰ(�����������ж�) ��������ж� ״̬�Ĵ���
                                                    0x5������ж���Ч����ʾ�������
                                                    0xA������ж���Ч���߼����ڴ����δ�������� */
        unsigned int  reserved_0: 12; /* bit[4-15] : ���� */
        unsigned int  reserved_1: 16; /* bit[16-31]: ���� */
    } reg;
} SOC_SCE_INT_SCE_UNION;
#endif
#define SOC_SCE_INT_SCE_sce_int_START   (0)
#define SOC_SCE_INT_SCE_sce_int_END     (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_INT_SCE_CLR_UNION
 �ṹ˵��  : INT_SCE_CLR �Ĵ����ṹ���塣��ַƫ����:0x02DC����ֵ:0x0000000A�����:32
 �Ĵ���˵��: �ж�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_clr : 4;  /* bit[0-3]  : ˵�������д0x5�����Ӧ�ж�Դ���߼�ֻ���յ�д0x5��ʱ�̲Ŷ��ж�Դ�������㡣 */
        unsigned int  reserved_0  : 12; /* bit[4-15] : ���� */
        unsigned int  reserved_1  : 16; /* bit[16-31]: ���� */
    } reg;
} SOC_SCE_INT_SCE_CLR_UNION;
#endif
#define SOC_SCE_INT_SCE_CLR_sce_int_clr_START  (0)
#define SOC_SCE_INT_SCE_CLR_sce_int_clr_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_FIFO_RX_WDATA_UNION
 �ṹ˵��  : FIFO_RX_WDATA �Ĵ����ṹ���塣��ַƫ����:0x02E0����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ն�fifo��д����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_rx_wdata : 32; /* bit[0-31]: �ն�fifo��д���� */
    } reg;
} SOC_SCE_FIFO_RX_WDATA_UNION;
#endif
#define SOC_SCE_FIFO_RX_WDATA_fifo_rx_wdata_START  (0)
#define SOC_SCE_FIFO_RX_WDATA_fifo_rx_wdata_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_FIFO_RX_RDATA_UNION
 �ṹ˵��  : FIFO_RX_RDATA �Ĵ����ṹ���塣��ַƫ����:0x02E4����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ն�fifo�Ķ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_rx_rdata : 32; /* bit[0-31]: �ն�fifo�Ķ����� */
    } reg;
} SOC_SCE_FIFO_RX_RDATA_UNION;
#endif
#define SOC_SCE_FIFO_RX_RDATA_fifo_rx_rdata_START  (0)
#define SOC_SCE_FIFO_RX_RDATA_fifo_rx_rdata_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_FIFO_TX_WDATA_UNION
 �ṹ˵��  : FIFO_TX_WDATA �Ĵ����ṹ���塣��ַƫ����:0x02E8����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����fifo��д����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_tx_wdata : 32; /* bit[0-31]: ����fifo��д���� */
    } reg;
} SOC_SCE_FIFO_TX_WDATA_UNION;
#endif
#define SOC_SCE_FIFO_TX_WDATA_fifo_tx_wdata_START  (0)
#define SOC_SCE_FIFO_TX_WDATA_fifo_tx_wdata_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_FIFO_TX_RDATA_UNION
 �ṹ˵��  : FIFO_TX_RDATA �Ĵ����ṹ���塣��ַƫ����:0x02EC����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����fifo�Ķ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_tx_rdata : 32; /* bit[0-31]: ����fifo�Ķ����� */
    } reg;
} SOC_SCE_FIFO_TX_RDATA_UNION;
#endif
#define SOC_SCE_FIFO_TX_RDATA_fifo_tx_rdata_START  (0)
#define SOC_SCE_FIFO_TX_RDATA_fifo_tx_rdata_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_PROT_UNION
 �ṹ˵��  : PROT �Ĵ����ṹ���塣��ַƫ����:0x02F0����ֵ:0x00000000�����:32
 �Ĵ���˵��: gm�Ŀ����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  dw_axi_gm_prot : 6;  /* bit[0-5] : gm��prot�źţ���Ϊ��3bit��дΪ��3bit��ÿ��3bit��bit1ʹ��sideband����������������ֵ */
        unsigned int  reserved       : 26; /* bit[6-31]:  */
    } reg;
} SOC_SCE_PROT_UNION;
#endif
#define SOC_SCE_PROT_dw_axi_gm_prot_START  (0)
#define SOC_SCE_PROT_dw_axi_gm_prot_END    (5)


/*****************************************************************************
 �ṹ��    : SOC_SCE_TP_MUX_UNION
 �ṹ˵��  : TP_MUX �Ĵ����ṹ���塣��ַƫ����:0x02F4����ֵ:0x00000000�����:32
 �Ĵ���˵��: testpointѡ���ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_tp_mux : 4;  /* bit[0-3] : testpointѡ���ź� */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_TP_MUX_UNION;
#endif
#define SOC_SCE_TP_MUX_sce_tp_mux_START  (0)
#define SOC_SCE_TP_MUX_sce_tp_mux_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CACHE_CTRL_UNION
 �ṹ˵��  : CACHE_CTRL �Ĵ����ṹ���塣��ַƫ����:0x300����ֵ:0x00000000�����:32
 �Ĵ���˵��: SCE AXI��дͨ·�Ƿ�֧��cacheable�����ı�־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mcache_wr : 4;  /* bit[0-3] : AXIдͨ���Ƿ�֧��cache�����ı�־
                                                    mcahce_wr[0]��Bufferable
                                                    mcahce_wr[1]��Cacheable
                                                    mcahce_wr[2]��Read Allocate
                                                    mcahce_wr[3]��Write Allocate
                                                    �����õ�ֵΪ4'b0000��4'b0010 */
        unsigned int  mcache_rd : 4;  /* bit[4-7] : AXI��ͨ���Ƿ�֧��cache�����ı�־
                                                    mcahce_rd[0]��Bufferable
                                                    mcahce_rd[1]��Cacheable
                                                    mcahce_rd[2]��Read Allocate
                                                    mcahce_rd[3]��Write Allocate
                                                    �����õ�ֵΪ4'b0000��4'b0010 */
        unsigned int  reserved  : 24; /* bit[8-31]:  */
    } reg;
} SOC_SCE_CACHE_CTRL_UNION;
#endif
#define SOC_SCE_CACHE_CTRL_mcache_wr_START  (0)
#define SOC_SCE_CACHE_CTRL_mcache_wr_END    (3)
#define SOC_SCE_CACHE_CTRL_mcache_rd_START  (4)
#define SOC_SCE_CACHE_CTRL_mcache_rd_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_SCE_RX_RES_BURST_UNION
 �ṹ˵��  : RX_RES_BURST �Ĵ����ṹ���塣��ַƫ����:0x304����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRL_RX�Ѿ����յ���burst����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_res_burst : 32; /* bit[0-31]: CTRL_RX�Ѿ����յ���burst���� */
    } reg;
} SOC_SCE_RX_RES_BURST_UNION;
#endif
#define SOC_SCE_RX_RES_BURST_cnt_res_burst_START  (0)
#define SOC_SCE_RX_RES_BURST_cnt_res_burst_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_RX_RES_WORD_UNION
 �ṹ˵��  : RX_RES_WORD �Ĵ����ṹ���塣��ַƫ����:0x308����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRL_RX�Ѿ����յ���word����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_res_word : 32; /* bit[0-31]: CTRL_RX�Ѿ����յ���word���� */
    } reg;
} SOC_SCE_RX_RES_WORD_UNION;
#endif
#define SOC_SCE_RX_RES_WORD_cnt_res_word_START  (0)
#define SOC_SCE_RX_RES_WORD_cnt_res_word_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_TX_REMAIN_BURST_UNION
 �ṹ˵��  : TX_REMAIN_BURST �Ĵ����ṹ���塣��ַƫ����:0x30C����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRL_TX��û�б����յ�burst����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_remain_burst : 32; /* bit[0-31]: CTRL_TX��û�б����յ�burst���� */
    } reg;
} SOC_SCE_TX_REMAIN_BURST_UNION;
#endif
#define SOC_SCE_TX_REMAIN_BURST_cnt_remain_burst_START  (0)
#define SOC_SCE_TX_REMAIN_BURST_cnt_remain_burst_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_TX_REMAIN_WORD_UNION
 �ṹ˵��  : TX_REMAIN_WORD �Ĵ����ṹ���塣��ַƫ����:0x310����ֵ:0x00000000�����:32
 �Ĵ���˵��: CTRL_TX��û�б����յ�word����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_remain_word : 32; /* bit[0-31]: CTRL_TX��û�б����յ�word���� */
    } reg;
} SOC_SCE_TX_REMAIN_WORD_UNION;
#endif
#define SOC_SCE_TX_REMAIN_WORD_cnt_remain_word_START  (0)
#define SOC_SCE_TX_REMAIN_WORD_cnt_remain_word_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AAD_LEN_UNION
 �ṹ˵��  : AAD_LEN �Ĵ����ṹ���塣��ַƫ����:0x0314����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������ݳ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aad_lenth : 32; /* bit[0-31]: ������ݳ���
                                                    ���ֽ�Ϊ��λ��֧�ַ�ΧΪ1-10M�ֽ� */
    } reg;
} SOC_SCE_AAD_LEN_UNION;
#endif
#define SOC_SCE_AAD_LEN_aad_lenth_START  (0)
#define SOC_SCE_AAD_LEN_aad_lenth_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_T_Q_LENTH_UNION
 �ṹ˵��  : T_Q_LENTH �Ĵ����ṹ���塣��ַƫ����:0x0318����ֵ:0x00000000�����:32
 �Ĵ���˵��: T_Q���ݳ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_t_lenth : 5;  /* bit[0-4]  : ccm_t_lenth */
        unsigned int  reserved_0  : 3;  /* bit[5-7]  :  */
        unsigned int  ccm_q_lenth : 3;  /* bit[8-10] : ccm��qֵ */
        unsigned int  reserved_1  : 1;  /* bit[11-11]:  */
        unsigned int  reserved_2  : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_T_Q_LENTH_UNION;
#endif
#define SOC_SCE_T_Q_LENTH_ccm_t_lenth_START  (0)
#define SOC_SCE_T_Q_LENTH_ccm_t_lenth_END    (4)
#define SOC_SCE_T_Q_LENTH_ccm_q_lenth_START  (8)
#define SOC_SCE_T_Q_LENTH_ccm_q_lenth_END    (10)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CCM_VER_FAIL_UNION
 �ṹ˵��  : CCM_VER_FAIL �Ĵ����ṹ���塣��ַƫ����:0x031c����ֵ:0x0000�����:32
 �Ĵ���˵��: CCMУ������־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_fail : 1;  /* bit[0]   : CCMУ������־����ƽ�ź�
                                                   0:У��ɹ�
                                                   1:У��ʧ�� */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_CCM_VER_FAIL_UNION;
#endif
#define SOC_SCE_CCM_VER_FAIL_ccm_fail_START  (0)
#define SOC_SCE_CCM_VER_FAIL_ccm_fail_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SCE_CCM_VER_FAIL_CLR_UNION
 �ṹ˵��  : CCM_VER_FAIL_CLR �Ĵ����ṹ���塣��ַƫ����:0x0320����ֵ:0x0000�����:32
 �Ĵ���˵��: CCMУ������־λclr�ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_fail_clr : 1;  /* bit[0]   : CCMУ������־λclr�ź�
                                                       0:��clr
                                                       1:clr���ź�λ */
        unsigned int  reserved     : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_CCM_VER_FAIL_CLR_UNION;
#endif
#define SOC_SCE_CCM_VER_FAIL_CLR_ccm_fail_clr_START  (0)
#define SOC_SCE_CCM_VER_FAIL_CLR_ccm_fail_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AES_KEY_PARITY_UNION
 �ṹ˵��  : AES_KEY_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0324����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY1����ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key_parity : 32; /* bit[0-31]: XTS KEY1����ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_SCE_AES_KEY_PARITY_UNION;
#endif
#define SOC_SCE_AES_KEY_PARITY_aes_key_parity_START  (0)
#define SOC_SCE_AES_KEY_PARITY_aes_key_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AES_KEY2_PARITY_UNION
 �ṹ˵��  : AES_KEY2_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0328����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY2����ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_parity : 32; /* bit[0-31]: XTS KEY2����ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_SCE_AES_KEY2_PARITY_UNION;
#endif
#define SOC_SCE_AES_KEY2_PARITY_aes_key2_parity_START  (0)
#define SOC_SCE_AES_KEY2_PARITY_aes_key2_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_KEY_REG_LOCK_UNION
 �ṹ˵��  : KEY_REG_LOCK �Ĵ����ṹ���塣��ַƫ����:0x32c����ֵ:0x0005�����:32
 �Ĵ���˵��: KEY_REG_LOCK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_reg_lock : 4;  /* bit[0-3] : key�Ĵ����Ķ�д������Ĭ��Ϊ0x5
                                                       0x5���������κ�key�Ĵ��������ɶ�д
                                                       0xa��δ������key�Ĵ����ɶ�д
                                                       ����ֵ�Ƿ� */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_KEY_REG_LOCK_UNION;
#endif
#define SOC_SCE_KEY_REG_LOCK_key_reg_lock_START  (0)
#define SOC_SCE_KEY_REG_LOCK_key_reg_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SCE_gcm_counter0_UNION
 �ṹ˵��  : gcm_counter0 �Ĵ����ṹ���塣��ַƫ����:0x0340+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: GCM��ʼֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gcm_counter0 : 32; /* bit[0-31]: GCM counter��ʼֵ,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_gcm_counter0_UNION;
#endif
#define SOC_SCE_gcm_counter0_gcm_counter0_START  (0)
#define SOC_SCE_gcm_counter0_gcm_counter0_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ccm_q_UNION
 �ṹ˵��  : ccm_q �Ĵ����ṹ���塣��ַƫ����:0x0380+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: ccm_q
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_q : 32; /* bit[0-31]: ccm_q,Qֵ��n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-1 */
    } reg;
} SOC_SCE_ccm_q_UNION;
#endif
#define SOC_SCE_ccm_q_ccm_q_START  (0)
#define SOC_SCE_ccm_q_ccm_q_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ccm_nonce_UNION
 �ṹ˵��  : ccm_nonce �Ĵ����ṹ���塣��ַƫ����:0x03c0+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: ccm_nonce
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_nonce : 32; /* bit[0-31]: ccm_nonce,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_ccm_nonce_UNION;
#endif
#define SOC_SCE_ccm_nonce_ccm_nonce_START  (0)
#define SOC_SCE_ccm_nonce_ccm_nonce_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_tweak_value_UNION
 �ṹ˵��  : tweak_value �Ĵ����ṹ���塣��ַƫ����:0x0400+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: tweak_value��ʼֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tweak_value : 32; /* bit[0-31]: tweak_value��ʼֵ,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_tweak_value_UNION;
#endif
#define SOC_SCE_tweak_value_tweak_value_START  (0)
#define SOC_SCE_tweak_value_tweak_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_xts_multi_data_UNION
 �ṹ˵��  : xts_multi_data �Ĵ����ṹ���塣��ַƫ����:0x0440+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: tweak_value��ʼֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xts_multi_data : 32; /* bit[0-31]: xts_multi_data��ʼֵ,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_xts_multi_data_UNION;
#endif
#define SOC_SCE_xts_multi_data_xts_multi_data_START  (0)
#define SOC_SCE_xts_multi_data_xts_multi_data_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_previous_ghash_digest_UNION
 �ṹ˵��  : previous_ghash_digest �Ĵ����ṹ���塣��ַƫ����:0x0480+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: previous_ghash_digest
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  previous_ghash_digest : 32; /* bit[0-31]: previous_ghash_digest,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_previous_ghash_digest_UNION;
#endif
#define SOC_SCE_previous_ghash_digest_previous_ghash_digest_START  (0)
#define SOC_SCE_previous_ghash_digest_previous_ghash_digest_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_aes_tag_out_UNION
 �ṹ˵��  : aes_tag_out �Ĵ����ṹ���塣��ַƫ����:0x04c0+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: aes_tag_out
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_tag_out : 32; /* bit[0-31]: aes_tag_out,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_aes_tag_out_UNION;
#endif
#define SOC_SCE_aes_tag_out_aes_tag_out_START  (0)
#define SOC_SCE_aes_tag_out_aes_tag_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_ccm_tag_out_4ver_UNION
 �ṹ˵��  : ccm_tag_out_4ver �Ĵ����ṹ���塣��ַƫ����:0x0500+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: ccm_tag_out_4ver
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_tag_out_4ver : 32; /* bit[0-31]: ccm_tag_out_4ver,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-3 */
    } reg;
} SOC_SCE_ccm_tag_out_4ver_UNION;
#endif
#define SOC_SCE_ccm_tag_out_4ver_ccm_tag_out_4ver_START  (0)
#define SOC_SCE_ccm_tag_out_4ver_ccm_tag_out_4ver_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AES_KEY1_UNION
 �ṹ˵��  : AES_KEY1 �Ĵ����ṹ���塣��ַƫ����:0x0540+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: AES_KEY1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  AES_KEY1 : 32; /* bit[0-31]: AES_KEY1,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-7 */
    } reg;
} SOC_SCE_AES_KEY1_UNION;
#endif
#define SOC_SCE_AES_KEY1_AES_KEY1_START  (0)
#define SOC_SCE_AES_KEY1_AES_KEY1_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AESKEY1_MASK_VALUE_UNION
 �ṹ˵��  : AESKEY1_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x0580����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY1����Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key1_mask_value : 32; /* bit[0-31]: KEY1����Կ����Ĵ��� */
    } reg;
} SOC_SCE_AESKEY1_MASK_VALUE_UNION;
#endif
#define SOC_SCE_AESKEY1_MASK_VALUE_aes_key1_mask_value_START  (0)
#define SOC_SCE_AESKEY1_MASK_VALUE_aes_key1_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AES_KEY2_UNION
 �ṹ˵��  : AES_KEY2 �Ĵ����ṹ���塣��ַƫ����:0x05C0+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: AES_KEY2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  AES_KEY2 : 32; /* bit[0-31]: AES_KEY2,n=0ʱ����Ӧ���ݵĸ�32λ,n�ķ�Χ0-7 */
    } reg;
} SOC_SCE_AES_KEY2_UNION;
#endif
#define SOC_SCE_AES_KEY2_AES_KEY2_START  (0)
#define SOC_SCE_AES_KEY2_AES_KEY2_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SCE_AESKEY2_MASK_VALUE_UNION
 �ṹ˵��  : AESKEY2_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x06a0����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY2����Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_mask_value : 32; /* bit[0-31]: KEY2����Կ����Ĵ��� */
    } reg;
} SOC_SCE_AESKEY2_MASK_VALUE_UNION;
#endif
#define SOC_SCE_AESKEY2_MASK_VALUE_aes_key2_mask_value_START  (0)
#define SOC_SCE_AESKEY2_MASK_VALUE_aes_key2_mask_value_END    (31)






/*****************************************************************************
  8 OTHERS����
*****************************************************************************/



/*****************************************************************************
  9 ȫ�ֱ�������
*****************************************************************************/


/*****************************************************************************
  10 ��������
*****************************************************************************/


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of soc_sce_interface.h */
