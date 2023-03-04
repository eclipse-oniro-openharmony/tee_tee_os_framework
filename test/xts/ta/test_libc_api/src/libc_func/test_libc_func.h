/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __TEST_LIBC_FUNC_H__
#define __TEST_LIBC_FUNC_H__

#include <tee_log.h>
#include <tee_time_api.h>

#define PTS_PASS        0
#define PTS_FAIL        1
#define PTS_UNRESOLVED  2
#define PTS_UNSUPPORTED 4
#define PTS_UNTESTED    5

int pthread_create_1_1();
int pthread_create_2_1();
int pthread_create_4_1();
int pthread_create_5_1();
int pthread_create_5_2();
int pthread_create_12_1();
int pthread_attr_destroy_1_1();
int pthread_attr_destroy_2_1();
int pthread_attr_destroy_3_1();
int pthread_attr_getstack_1_1();
int pthread_attr_getstacksize_1_1();
int pthread_attr_init_1_1();
int pthread_attr_init_3_1();
int pthread_attr_init_4_1();
int pthread_attr_setstack_1_1();
int pthread_attr_setstack_2_1();
int pthread_attr_setstack_4_1();
int pthread_attr_setstack_6_1();
int pthread_attr_setstack_7_1();
int pthread_attr_setstacksize_1_1();
int pthread_attr_setstacksize_2_1();
int pthread_attr_setstacksize_4_1();
int pthread_exit_2_1();
int pthread_exit_3_1();
int pthread_mutex_destroy_1_1();
int pthread_once_1_1();
int pthread_spin_destroy_1_1();
int pthread_spin_trylock_4_1();
int pthread_mutexattr_getprotocol_1_1();
int pthread_mutexattr_gettype_1_1();
int test_sem();

//pthread
int pthread_once_1_3();
int pthread_once_2_1();
int pthread_exit_0_1();
int pthread_exit_0_2();
int pthread_exit_1_1_0();
int pthread_exit_3_1_0();
int pthread_mutex_init_1_1();
int pthread_mutex_init_2_1_0();
int pthread_mutex_init_3_1();
int pthread_mutex_lock_0_1();
int pthread_mutex_lock_0_2();
int pthread_mutex_lock_0_3();
int pthread_mutex_lock_1_1_0();
int pthread_mutex_trylock_0_1();
int pthread_mutex_trylock_1_1();
int pthread_mutex_trylock_4_1();
int pthread_mutex_unlock_1_1();
int pthread_mutex_destroy_1_1_0();
int pthread_mutex_destroy_2_1();
int pthread_mutex_destroy_4_2();
int pthread_spin_init_1_1();
int pthread_spin_lock_0_1();
int pthread_spin_lock_0_2();
int pthread_spin_lock_0_3();
int pthread_spin_lock_1_2();
int pthread_spin_trylock_0_1();
int pthread_spin_trylock_1_1();
int pthread_spin_unlock_1_1();
int pthread_cond_broadcast_1_1();
int pthread_cond_init_1_1();
int pthread_cond_signal_1_1();
int pthread_cond_wait_0_1();
int pthread_cond_wait_0_2();
int pthread_cond_wait_0_3();
int pthread_cond_wait_1_1();
int pthread_cond_wait_2_1();
int pthread_join_1_1();
int pthread_join_2_1();
int test_pthread_key_create();
int test_pthread_equal();
int pthread_getspecific_1_1();
int pthread_setspecific_1_2();

//mem
int do_test_calloc();
int do_test_malloc();
int do_test_free();
int do_test_free_1();
int test_mmap();

//math
int do_test_atan(void);
int do_test_ceil(void);
int do_test_ceilf(void);
int do_test_exp(void);
int do_test_fabs(void);
int do_test_floor(void);
int do_test_frexpl(void);
int do_test_log(void);
int do_test_log2(void);
int do_test_pow(void);
int do_test_roundf(void);
int do_test_sqrt(void);

//stdlib
int do_test_stdlib(void);
int do_test_strtol(void);
int do_test_getenv(void);

//ctype
int do_test_ctype(void);
int do_test_wctype(void);
int do_test_towfun(void);

//time
int do_test_clock_gettime(void);
int do_test_strftime(void);

//stdio
int do_test_vsprintf(void);
int do_test_sprintf(void);
int do_test_fflush(void);
int do_test_stdio(void);

//error
int test_error(void);

//unistd
int do_test_getpid(void);

//locale
int do_test_strtod1(void);
int do_test_strtod2(void);
int do_test_strtod3(void);
int do_test_strcoll(void);
int test_strxfrm(void);

//multibyte
int do_test_mbrtowc(void);
int do_test_wcrtomb(void);
int do_test_wctob(void);

//prng
int do_test_random(void);
int do_test_srandom(void);

//string
int do_test_memcmp(void);
int do_test_strcmp(void);
int do_test_strchr(void);
int do_test_strlen(void);
int do_test_memset(void);
int do_test_memmove(void);
int do_test_memcpy(void);
int do_test_wmemchr(void);
int do_test_wcslen(void);

#endif


