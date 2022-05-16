#include "libc.h"
#include "tee_time_api.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <dlfcn.h>
#include <lib_timer.h>
#include <hmlog.h>

const char __utc[] = "UTC";

/*
 * true time works on mobile
 * but hongmeng has no true time on qemu platform
 * so use fake time for qemu running
 * so pthread_cond_timedwait/pthread_cond_wait works with no timeout
 * but pthread_cond_timedwait/pthread_cond_wait with timeout not works
 */
#ifdef CONFIG_PLAT_VIRT
void __fake_time(TEE_Time *time)
{
	if (time == NULL)
		return;
	time->seconds = 0;
	time->millis = 0;
}

weak_alias(__fake_time, get_sys_rtc_time);
weak_alias(__fake_time, TEE_GetSystemTime);
#else
void TEE_GetSystemTime(TEE_Time *) __attribute__((weak_import));
void get_sys_rtc_time(TEE_Time *) __attribute__((weak_import));
#endif

static void (*g_get_system_time_hdl)(TEE_Time *time) = NULL;
static void (*g_get_sys_rtctime_hdl)(TEE_Time *time) = NULL;

static int get_timer_hdl(void)
{
#ifdef __aarch64__
	static const char *libtee_shared_name = "libtee_shared.so";
#else
	static const char *libtee_shared_name = "libtee_shared_a32.so";
#endif
	static void *libtee_shared_hdl = NULL;

	if (libtee_shared_hdl != NULL)
		return 0;

	libtee_shared_hdl = dlopen(libtee_shared_name, RTLD_NOW | RTLD_LOCAL);
	if (libtee_shared_hdl == NULL) {
		hm_error("load tee shared library failed\n");
		return -1;
	}
	g_get_system_time_hdl = dlsym(libtee_shared_hdl, "TEE_GetSystemTime");
	if (g_get_system_time_hdl == NULL) {
		hm_error("get get system time hdl failed\n");
		goto error;
	}
	g_get_sys_rtctime_hdl = dlsym(libtee_shared_hdl, "get_sys_rtc_time");
	if (g_get_sys_rtctime_hdl == NULL) {
		hm_error("get sys rtc time hdl failed\n");
		goto error;
	}
	return 0;
error:
	dlclose(libtee_shared_hdl);
	libtee_shared_hdl = NULL;
	return -1;
}

static void get_rtc_time(TEE_Time *time)
{
	if (get_timer_hdl() == 0) {
		g_get_sys_rtctime_hdl(time);
	} else {
		time->seconds = 0;
		time->millis = 0;
	}
}
static void get_system_time(TEE_Time *time)
{
	if (get_timer_hdl() == 0) {
		g_get_system_time_hdl(time);
	} else {
		time->seconds = 0;
		time->millis = 0;
	}
}

int __clock_gettime(clockid_t clk, struct timespec *ts)
{
	return clock_gettime(clk, ts);
}

int clock_gettime(clockid_t clk, struct timespec *ts)
{
	TEE_Time time;

	if (ts == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch (clk) {
	case CLOCK_REALTIME:
	case CLOCK_REALTIME_COARSE:
		if (get_sys_rtc_time != NULL)
			get_sys_rtc_time(&time);
		else
			get_rtc_time(&time);
		ts->tv_sec = (time_t)time.seconds;
		ts->tv_nsec = (long)time.millis * 1000000;
		break;
	case CLOCK_BOOTTIME:
	case CLOCK_MONOTONIC:
		if (TEE_GetSystemTime != NULL)
			TEE_GetSystemTime(&time);
		else
			get_system_time(&time);
		ts->tv_sec = (time_t)time.seconds;
		ts->tv_nsec = (long)time.millis * 1000000;
		break;
	// NOTE: support more clock id: CLOCK_THREAD_CPUTIME_ID
	// CLOCK_PROCESS_CPUTIME_ID
	default:
		errno = EINVAL;
		return -1;
	}
	return 0;
}
