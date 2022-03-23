/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: internal debug define.
 * Author: sdk
 * Create: 2017-05-31
 */

#ifndef __HI_LOG_H__
#define __HI_LOG_H__

#include "hi_type_dev.h"
#include "hi_tee_module_id.h"

#define HI_LOG_MARK

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CFG_HI_TEE_LOG_LEVEL
#define CFG_HI_TEE_LOG_LEVEL        (0)
#endif

/* allow modules to modify, If the related module does not define it, no information output */
#ifndef HI_LOG_D_FUNCTRACE
#define HI_LOG_D_FUNCTRACE          (0)
#endif

/* allow modules to modify, If the related module does not define it, no information output */
#ifndef HI_LOG_D_UNFTRACE
#define HI_LOG_D_UNFTRACE           (0)
#endif

/* allow modules to modify, default value is HI_ID_STB, the general module id */
#ifndef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_SYS
#endif

#define HI_LOG_MAX_TRACE_LEN    (256)

/*
 * Level of the output debugging information.
 * CNcomment: ������Ϣ�������.
 */
typedef enum {
    /* Alert information.
     * It indicates that a important exception occurs in the system.action must be taken immediately
     * CNcomment: ������Ϣ, �����ӡ��BBOX��̨��־�ռ�ϵͳ��
     *            �û�ϵͳ��Ҫ״̬�仯���ǳ���Ҫ���쳣��
     */
    HI_LOG_LEVEL_ALERT   = 0,
    /* Fatal error.
     * It indicates that a Fatal problem occurs in the system. Therefore, you must pay attention to it
     * CNcomment: ��������, ���������Ҫ�ر��ע��һ����ִ���������ϵͳ�������ش�����
     */
    HI_LOG_LEVEL_FATAL   = 1,
    /* Major error.
     * It indicates that a major problem occurs in the system and the system cannot run
     * CNcomment: һ�����, һ����ִ���������ϵͳ�����˱Ƚϴ�����⣬��������������
     */
    HI_LOG_LEVEL_ERROR   = 2,
    /* Warning.
     * It indicates that a minor problem occurs in the system, but the system still can run properly
     * CNcomment: �澯��Ϣ, һ����ִ�����Ϣ����ϵͳ���ܳ������⣬���ǻ��ܼ�������
     */
    HI_LOG_LEVEL_WARNING = 3,
    /* Notice.
     * It is used to prompt users. Users can open the message when locating problems.
     * CNcomment: ��������Ҫ����Ϣ, һ�������ϵͳ�Ĺؼ�·��������
     */
    HI_LOG_LEVEL_NOTICE  = 4,
    /* INFO.
     * It is used to prompt users. Users can open the message when locating problems.
     * It is recommended to disable this message in general.
     * CNcomment: ��ʾ��Ϣ, һ����Ϊ�����û���������ڶ�λ�����ʱ����Դ򿪣�һ������½���ر�
     */
    HI_LOG_LEVEL_INFO    = 5,
    /* Debug.
     * It is used to prompt developers. Developers can open the message when locating problems
     * It is recommended to disable this message in general.
     * CNcomment: ��ʾ��Ϣ, һ����Ϊ������Ա����������趨�Ĵ�ӡ����һ������½���ر�
     */
    HI_LOG_LEVEL_DBG     = 6,
    /* Trace.
     * It is used to track the entry and exit of function when the interface is called.
     * CNcomment: ��ʾ��Ϣ��һ�����ڸ��ٽӿڵ���ʱ�����Ľ������˳�
     */
    HI_LOG_LEVEL_TRACE   = 7,
    HI_LOG_LEVEL_MAX
} hi_tee_log_level;

/* Just only for alert level print. */   /* CNcomment: Ϊ�˴�ӡ�澯��Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_ALERT    (0)
/* Just only for fatal level print. */   /* CNcomment: Ϊ�˴�ӡ������Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_FATAL    (1)
/* Just only for error level print. */   /* CNcomment: Ϊ�˴�ӡ������Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_ERROR    (2)
/* Just only for warning level print. */ /* CNcomment: Ϊ�˴�ӡ������Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_WARN     (3)
/* Just only for notice level print.  */ /* CNcomment: Ϊ�˴�ӡע����Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_NOTICE   (4)
/* Just only for info level print. */    /* CNcomment: Ϊ�˴�ӡ��Ϣ������ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_INFO     (5)
/* Just only for debug level print. */   /* CNcomment: Ϊ�˴�ӡ������Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_DBG      (6)
/* Just only for trace level print. */   /* CNcomment: Ϊ�˴�ӡ�ӿڸ�����Ϣ���ƶ��ĺ��ӡ���� */
#define HI_TRACE_LEVEL_TRACE    (7)

/* Just only debug output, MUST BE NOT calling it.
 * CNcomment: ���������Ϣ�ӿڣ����Ƽ�ֱ�ӵ��ô˽ӿ�
 */
hi_void hi_log_print(hi_u32 log_level, hi_u32 module_id, const hi_u8 *func_name,
                     hi_u32 line_num, const hi_char *format, ...);

/* CNcomment: ���������Ϣ�ӿڣ��������Ϣ�������� */
hi_void hi_log_simple_print(const hi_char *format, ...);

/* CNcomment: ��ӡ������ */
hi_void hi_log_print_block(hi_u32 level, hi_u32 module_id, hi_char *block, hi_u32 size);

#ifdef ENABLE_FUNC_LINE
#define  HI_LOG_LINE  __LINE__
#else
#define  HI_LOG_LINE  0
#endif

#ifdef CFG_HI_TEE_LOG_SUPPORT
#define hi_trace(level, module_id, fmt...) do {                                     \
    hi_log_print(level, (hi_u32)module_id, (hi_u8*)__FUNCTION__, HI_LOG_LINE, fmt); \
} while (0)

#define hi_simple_trace(fmt...) do { \
    hi_log_simple_print(fmt);    \
} while (0)

#if (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_ALERT)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)
#define hi_log_err(fmt...)
#define hi_log_warn(fmt...)
#define hi_log_notice(fmt...)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)
#define hi_err_print_block(block, size)
#define hi_warn_print_block(block, size)
#define hi_notice_print_block(block, size)
#define hi_info_print_block(block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_FATAL)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)
#define hi_log_warn(fmt...)
#define hi_log_notice(fmt...)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)
#define hi_warn_print_block(block, size)
#define hi_notice_print_block(block, size)
#define hi_info_print_block(block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_ERROR)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR, LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)
#define hi_log_notice(fmt...)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR, LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)
#define hi_notice_print_block(block, size)
#define hi_info_print_block(block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_WARN)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR, LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)                 hi_trace(HI_TRACE_LEVEL_WARN,  LOG_MODULE_ID, fmt)
#define hi_log_notice(fmt...)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT, LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL, LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR, LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_WARN,  LOG_MODULE_ID, block, size)
#define hi_notice_print_block(block, size)
#define hi_info_print_block(block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_NOTICE)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)                 hi_trace(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, fmt)
#define hi_log_notice(fmt...)               hi_trace(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, fmt)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, block, size)
#define hi_notice_print_block(block, size)  hi_log_print_block(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, block, size)
#define hi_info_print_block(block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_INFO)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)                 hi_trace(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, fmt)
#define hi_log_notice(fmt...)               hi_trace(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, fmt)
#define hi_log_info(fmt...)                 hi_trace(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, fmt)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, block, size)
#define hi_notice_print_block(block, size)  hi_log_print_block(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, block, size)
#define hi_info_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, block, size)
#define hi_dbg_print_block(block, size)
#elif (CFG_HI_TEE_LOG_LEVEL == HI_TRACE_LEVEL_DBG)
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)                 hi_trace(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, fmt)
#define hi_log_notice(fmt...)               hi_trace(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, fmt)
#define hi_log_info(fmt...)                 hi_trace(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, fmt)
#define hi_log_dbg(fmt...)                  hi_trace(HI_TRACE_LEVEL_DBG,    LOG_MODULE_ID, fmt)
#define hi_log_trace(fmt...)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, block, size)
#define hi_notice_print_block(block, size)  hi_log_print_block(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, block, size)
#define hi_info_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, block, size)
#define hi_dbg_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_DBG,    LOG_MODULE_ID, block, size)
#else
#define hi_log_alert(fmt...)                hi_trace(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, fmt)
#define hi_log_fatal(fmt...)                hi_trace(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, fmt)
#define hi_log_err(fmt...)                  hi_trace(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, fmt)
#define hi_log_warn(fmt...)                 hi_trace(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, fmt)
#define hi_log_notice(fmt...)               hi_trace(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, fmt)
#define hi_log_info(fmt...)                 hi_trace(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, fmt)
#define hi_log_dbg(fmt...)                  hi_trace(HI_TRACE_LEVEL_DBG,    LOG_MODULE_ID, fmt)
#define hi_log_trace(fmt...)                hi_trace(HI_TRACE_LEVEL_TRACE,  LOG_MODULE_ID, fmt)

#define hi_alert_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_ALERT,  LOG_MODULE_ID, block, size)
#define hi_fatal_print_block(block, size)   hi_log_print_block(HI_TRACE_LEVEL_FATAL,  LOG_MODULE_ID, block, size)
#define hi_err_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_ERROR,  LOG_MODULE_ID, block, size)
#define hi_warn_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_WARN,   LOG_MODULE_ID, block, size)
#define hi_notice_print_block(block, size)  hi_log_print_block(HI_TRACE_LEVEL_NOTICE, LOG_MODULE_ID, block, size)
#define hi_info_print_block(block, size)    hi_log_print_block(HI_TRACE_LEVEL_INFO,   LOG_MODULE_ID, block, size)
#define hi_dbg_print_block(block, size)     hi_log_print_block(HI_TRACE_LEVEL_DBG,    LOG_MODULE_ID, block, size)
#endif

#else
#define hi_log_alert(fmt...)
#define hi_log_fatal(fmt...)
#define hi_log_err(fmt...)
#define hi_log_warn(fmt...)
#define hi_log_notice(fmt...)
#define hi_log_info(fmt...)
#define hi_log_dbg(fmt...)
#define hi_log_trace(fmt...)
#endif

/* function trace log, strictly prohibited to expand */
#define hi_alert_print_err_code(err_code) hi_log_alert("Error Code: [0x%08X]\n", err_code)
/* function trace log, print the called function name when function is error */
#define hi_alert_print_call_fun_err(func, err_code) hi_log_alert("Call %s Failed, Error Code: [0x%08X]\n", #func, err_code)
/* Function trace log, print the pointer name when pointer is null */
#define hi_alert_print_null_pointer(val) hi_log_alert("%s = %p,  Null Pointer!\n", #val, val)

/* function trace log, strictly prohibited to expand */
#define hi_fatal_print_err_code(err_code) hi_log_fatal("Error Code: [0x%08X]\n", err_code)
/* function trace log, print the called function name when function is error */
#define hi_fatal_print_call_fun_err(func, err_code) hi_log_fatal("Call %s Failed, Error Code: [0x%08X]\n", #func, err_code)
/* Function trace log, print the pointer name when pointer is null */
#define hi_fatal_print_null_pointer(val) hi_log_fatal("%s = %p,  Null Pointer!\n", #val, val)

/* function trace log, strictly prohibited to expand */
#define hi_err_print_err_code(err_code) hi_log_err("Error Code: [0x%08X]\n", err_code)
/* function trace log, print the called function name when function is error */
#define hi_err_print_call_fun_err(func, err_code) hi_log_err("Call %s Failed, Error Code: [0x%08X]\n", #func, err_code)
/* Function trace log, print the pointer name when pointer is null */
#define hi_err_print_null_pointer(val) hi_log_err("%s = %p,  Null Pointer!\n", #val, val)

/* function trace log, strictly prohibited to expand */
#define hi_warn_print_err_code(err_code) hi_log_warn("Error Code: [0x%08X]\n", err_code)
/* function trace log, print the called function name when function is error */
#define hi_warn_print_call_fun_err(func, err_code) hi_log_warn("Call %s Failed, Error Code: [0x%08X]\n", #func, err_code)
/* Function trace log, print the pointer name when pointer is null */
#define hi_warn_print_null_pointer(val) hi_log_warn("%s = %p,  Null Pointer!\n", #val, val)

/* Used for displaying more detailed alert information */
#define hi_alert_print_s32(val)   hi_log_alert("%s = %d\n",        #val, val)
#define hi_alert_print_u32(val)   hi_log_alert("%s = %u\n",        #val, val)
#define hi_alert_print_s64(val)   hi_log_alert("%s = %lld\n",      #val, val)
#define hi_alert_print_u64(val)   hi_log_alert("%s = %llu\n",      #val, val)
#define hi_alert_print_h32(val)   hi_log_alert("%s = 0x%08X\n",    #val, val)
#define hi_alert_print_h64(val)   hi_log_alert("%s = 0x%016llX\n", #val, val)
#define hi_alert_print_str(val)   hi_log_alert("%s = %s\n",        #val, val)
#define hi_alert_print_void(val)  hi_log_alert("%s = %p\n",        #val, val)
#define hi_alert_print_float(val) hi_log_alert("%s = %f\n",        #val, val)
#define hi_alert_print_bool(val)  hi_log_alert("%s = %s\n",        #val, val ? "True" : "False")
#define hi_alert_print_info(val)  hi_log_alert("<%s>\n",            val)

/* Used for displaying more detailed fatal information */
#define hi_fatal_print_s32(val)   hi_log_fatal("%s = %d\n",        #val, val)
#define hi_fatal_print_u32(val)   hi_log_fatal("%s = %u\n",        #val, val)
#define hi_fatal_print_s64(val)   hi_log_fatal("%s = %lld\n",      #val, val)
#define hi_fatal_print_u64(val)   hi_log_fatal("%s = %llu\n",      #val, val)
#define hi_fatal_print_h32(val)   hi_log_fatal("%s = 0x%08X\n",    #val, val)
#define hi_fatal_print_h64(val)   hi_log_fatal("%s = 0x%016llX\n", #val, val)
#define hi_fatal_print_str(val)   hi_log_fatal("%s = %s\n",        #val, val)
#define hi_fatal_print_void(val)  hi_log_fatal("%s = %p\n",        #val, val)
#define hi_fatal_print_float(val) hi_log_fatal("%s = %f\n",        #val, val)
#define hi_fatal_print_bool(val)  hi_log_fatal("%s = %s\n",        #val, val ? "True" : "False")
#define hi_fatal_print_info(val)  hi_log_fatal("<%s>\n",            val)

/* Used for displaying more detailed error information */
#define hi_err_print_s32(val)     hi_log_err("%s = %d\n",        #val, val)
#define hi_err_print_u32(val)     hi_log_err("%s = %u\n",        #val, val)
#define hi_err_print_s64(val)     hi_log_err("%s = %lld\n",      #val, val)
#define hi_err_print_u64(val)     hi_log_err("%s = %llu\n",      #val, val)
#define hi_err_print_h32(val)     hi_log_err("%s = 0x%08X\n",    #val, val)
#define hi_err_print_h64(val)     hi_log_err("%s = 0x%016llX\n", #val, val)
#define hi_err_print_str(val)     hi_log_err("%s = %s\n",        #val, val)
#define hi_err_print_void(val)    hi_log_err("%s = %p\n",        #val, val)
#define hi_err_print_float(val)   hi_log_err("%s = %f\n",        #val, val)
#define hi_err_print_bool(val)    hi_log_err("%s = %s\n",        #val, val ? "True" : "False")
#define hi_err_print_info(val)    hi_log_err("<%s>\n",            val)

/* Used for displaying more detailed warning information */
#define hi_warn_print_s32(val)    hi_log_warn("%s = %d\n",        #val, val)
#define hi_warn_print_u32(val)    hi_log_warn("%s = %u\n",        #val, val)
#define hi_warn_print_s64(val)    hi_log_warn("%s = %lld\n",      #val, val)
#define hi_warn_print_u64(val)    hi_log_warn("%s = %llu\n",      #val, val)
#define hi_warn_print_h32(val)    hi_log_warn("%s = 0x%08X\n",    #val, val)
#define hi_warn_print_h64(val)    hi_log_warn("%s = 0x%016llX\n", #val, val)
#define hi_warn_print_str(val)    hi_log_warn("%s = %s\n",        #val, val)
#define hi_warn_print_void(val)   hi_log_warn("%s = %p\n",        #val, val)
#define hi_warn_print_float(val)  hi_log_warn("%s = %f\n",        #val, val)
#define hi_warn_print_bool(val)   hi_log_warn("%s = %s\n",        #val, val ? "True" : "False")
#define hi_warn_print_info(val)   hi_log_warn("<%s>\n",            val)

/* Used for displaying more detailed key info information */
#define hi_notice_print_s32(val)    hi_log_notice("%s = %d\n",        #val, val)
#define hi_notice_print_u32(val)    hi_log_notice("%s = %u\n",        #val, val)
#define hi_notice_print_s64(val)    hi_log_notice("%s = %lld\n",      #val, val)
#define hi_notice_print_u64(val)    hi_log_notice("%s = %llu\n",      #val, val)
#define hi_notice_print_h32(val)    hi_log_notice("%s = 0x%08X\n",    #val, val)
#define hi_notice_print_h64(val)    hi_log_notice("%s = 0x%016llX\n", #val, val)
#define hi_notice_print_str(val)    hi_log_notice("%s = %s\n",        #val, val)
#define hi_notice_print_void(val)   hi_log_notice("%s = %p\n",        #val, val)
#define hi_notice_print_float(val)  hi_log_notice("%s = %f\n",        #val, val)
#define hi_notice_print_bool(val)   hi_log_notice("%s = %s\n",        #val, val ? "True" : "False")
#define hi_notice_print_info(val)   hi_log_notice("<%s>\n",            val)

/* Only used for key info, Can be expanded as needed */
#define hi_info_print_s32(val)    hi_log_info("%s = %d\n",        #val, val)
#define hi_info_print_u32(val)    hi_log_info("%s = %u\n",        #val, val)
#define hi_info_print_s64(val)    hi_log_info("%s = %lld\n",      #val, val)
#define hi_info_print_u64(val)    hi_log_info("%s = %llu\n",      #val, val)
#define hi_info_print_h32(val)    hi_log_info("%s = 0x%08X\n",    #val, val)
#define hi_info_print_h64(val)    hi_log_info("%s = 0x%016llX\n", #val, val)
#define hi_info_print_str(val)    hi_log_info("%s = %s\n",        #val, val)
#define hi_info_print_void(val)   hi_log_info("%s = %p\n",        #val, val)
#define hi_info_print_float(val)  hi_log_info("%s = %f\n",        #val, val)
#define hi_info_print_bool(val)   hi_log_info("%s = %s\n",        #val, val ? "True" : "False")
#define hi_info_print_info(val)   hi_log_info("<%s>\n",            val)

/* Only used for self debug, Can be expanded as needed */
#define hi_dbg_print_s32(val)     hi_log_dbg("%s = %d\n",        #val, val)
#define hi_dbg_print_u32(val)     hi_log_dbg("%s = %u\n",        #val, val)
#define hi_dbg_print_s64(val)     hi_log_dbg("%s = %lld\n",      #val, val)
#define hi_dbg_print_u64(val)     hi_log_dbg("%s = %llu\n",      #val, val)
#define hi_dbg_print_h32(val)     hi_log_dbg("%s = 0x%08X\n",    #val, val)
#define hi_dbg_print_h64(val)     hi_log_dbg("%s = 0x%016llX\n", #val, val)
#define hi_dbg_print_str(val)     hi_log_dbg("%s = %s\n",        #val, val)
#define hi_dbg_print_void(val)    hi_log_dbg("%s = %p\n",        #val, val)
#define hi_dbg_print_float(val)   hi_log_dbg("%s = %f\n",        #val, val)
#define hi_dbg_print_bool(val)    hi_log_dbg("%s = %s\n",        #val, val ? "True" : "False")
#define hi_dbg_print_info(val)    hi_log_dbg("<%s>\n",            val)

/* define function trace */
#define hi_notice_func_enter() hi_log_notice(" ===>[Enter]\n")
#define hi_notice_func_exit()  hi_log_notice(" <===[Exit]\n")
#define hi_notice_func_trace() hi_log_notice(" =TRACE=\n")

#define hi_info_func_enter() hi_log_info(" ===>[Enter]\n")
#define hi_info_func_exit()  hi_log_info(" <===[Exit]\n")
#define hi_info_func_trace() hi_log_info(" =TRACE=\n")

#define hi_dbg_func_enter() hi_log_dbg(" ===>[Enter]\n")
#define hi_dbg_func_exit()  hi_log_dbg(" <===[Exit]\n")
#define hi_dbg_func_trace() hi_log_dbg(" =TRACE=\n")

#define mk_str(exp) # exp
#define mk_marco_to_str(exp) mk_str(exp)
#define VERSION_STRING ("SDK_VERSION: [" mk_marco_to_str(SDK_VERSION) "] Build Time: [" __DATE__ ", " __TIME__ "]")
#define USER_VERSION_STRING ("SDK_VERSION: [" mk_marco_to_str(SDK_VERSION) "]")

#define hi_check_result(func) do {                   \
    hi_s32 err_code_ = func;                         \
    if (err_code_ != 0) {                            \
        hi_err_print_call_fun_err(#func, err_code_); \
    }                                                \
} while (0)

#ifdef __cplusplus
}
#endif

#endif  /* __HI_LOG_H__ */

