#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <api/kc_tcb.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <procmgr.h>
#include <sys/hmapi.h>
#include <sys/kuapi.h>
#include "hm/thread.h"
#include "pthread_impl.h"
#include <hmlog.h>
#include <hm_thread.h>
#include <cs.h>
#include <securec.h>
#include <asan.h>
#include "stdio_impl.h"

extern uintptr_t __stack_chk_guard;

/*
  We need to get a unique id for thread for mutex.
*/
#define UNIQUE_ID_FOR_MUTEX (hmapi_tls_get()->thread_handler)

unsigned long thread_tid()
{
	int tid = hmapi_get_tid();
	if (tid < 0)
		hm_panic("get tid failed\n");
	return (unsigned long)tid;
}

/* Initialized local thread storage */
static void init_tls(struct hmapi_thread_local_storage *tls)
{
	tls->thread_handler = hmapi_tcb_cref(); // cref for the current tcb
	tls->thread_id =
		hmapi_get_tid();       // thread id for the current tcb this function has checked return value
	tls->cnode_cref = hmapi_cnode_cref();   // cnode for the current tcb
	tls->aspace = hmapi_aspace_cref();		// aspace for the current tcb
	tls->stack_top = 0;
	tls->msghdl = 0;
	tls->thread_ptr = 0;
	tls->thread_local_heap = 0;
	for (int i = 0; i < (int)hmobj_MAX; ++i)
		tls->current_pmem[i] = 0;
	tls->ch_cref[0] = 0;
	tls->ch_cref[1] = 0;
	tls->timer_cref[0] = 0;
	tls->timer_cref[1] = 0;

	if (is_ref_err(tls->thread_handler) ||
	    tls->thread_id < 0 ||
	    is_ref_err(tls->cnode_cref) ||
	    is_ref_err(tls->aspace))
		hm_panic("tls variable init failed\n");

	hmapi_tls_init(tls);
}

void thread_func_wrapper(void *(*func)(void *), struct pthread *arg,
			 unsigned long stack_top)
{
	struct hmapi_thread_local_storage tls;
	void *ret_attr = NULL;
	struct pthread *self = NULL;

	if (func == NULL || arg == NULL)
		hm_panic("invalid func or arg for wrapper\n");
	self = arg;

	/* Local storage is alloced on the stack.
	 * This will work since the thread will not be freed before the thread quit */
	init_tls(&tls);
	tls.thread_ptr = arg;
	tls.stack_top = stack_top;
	self->tid = (uint64_t)tls.thread_id;

	ret_attr = (*func)(arg->start_arg);

	/* there are chances that pthread_exit might return EAGAIN */
	pthread_exit(ret_attr);
	hm_panic("thread_exit should not return for wrapper\n");
}

#ifdef CONFIG_ENABLE_TEESMP
static int thread_create_ipc(cref_t *channel)
{
	cref_t msghdl;
	struct hmapi_thread_local_storage *tls = NULL;

	msghdl = hm_msg_create_hdl();
	if (is_ref_err(msghdl)) {
		hm_error("create msg_hdl failed\n");
		return -1;
	}

	/* get self tls, and store msghdl in it */
	tls = hmapi_tls_get();
	if (tls == NULL) {
		hm_error("get tls failed");
		goto err_get_tls;
	}
	tls->msghdl = msghdl;

	/* we create one channel here */
	int rc = hm_create_ipc_channel(NULL, channel, true, false, false);
	if (rc != 0) {
		hm_error("create ipc channel failed, rc=%d\n", rc);
		goto err_create_ipc_chnl;
	}
	return 0;
err_create_ipc_chnl:
	tls->msghdl = 0;
err_get_tls:
	hm_msg_delete_hdl(hmapi_cnode_cref(), msghdl);
	return -1;
}

static void thread_delete_ipc(cref_t channel)
{
	struct hmapi_thread_local_storage *tls = NULL;

	/* we only create one channel, it's channel num is 0 */
	int rc = hm_remove_ipc_channel(get_selfpid(), NULL, 0, channel);
	if (rc != 0)
		hm_error("remove ipc channel failed, rc=%d\n", rc);

	tls = hmapi_tls_get();
	if (tls == NULL) {
		hm_error("get tls failed");
		return;
	}
	hm_msg_delete_hdl(hmapi_cnode_cref(), tls->msghdl);
	tls->msghdl = 0;
}

void thread_func_kick_wrapper(void *(*func)(void *), struct pthread *arg,
			      unsigned long stack_top)
{
	struct hmapi_thread_local_storage tls;
	void *ret_attr = NULL;
	struct pthread *self = NULL;

	if (func == NULL || arg == NULL)
		hm_panic("invalid func or arg for kick wrapper\n");

	init_tls(&tls);
	tls.thread_ptr = arg;
	tls.stack_top = stack_top;
	self = arg;
	self->tid = (uint64_t)tls.thread_id;

	/* syscall to do spi_notify and set affinity to 0 (in the syscall) */
	teecall_spi_notify_shadow();

	cref_t channel;
	int ret = thread_create_ipc(&channel);
	if (ret != 0)
		hm_error("this thread create ipc channel failed");

	ret_attr = (*func)(arg->start_arg);

	if (ret == 0)
		thread_delete_ipc(channel);

	pthread_exit(ret_attr);
	hm_panic("thread_exit should not return for kick wrapper");
}
#endif

int set_thread_priority(cref_t thread, int priority)
{
	int orig_prio;

	if (is_ref_err(thread))
		return -1;
	orig_prio = hmex_thread_set_priority(thread, (unsigned int)priority);
	if (orig_prio < 0) {
		return orig_prio;
	}
	return 0;
}

// as the robust list head is in this structure.
// when process exiting, it will access this memory.
// so put it to global variable, not in stack.
static struct pthread pthread_main;
int main(int argc, char *argv[], char *envp[]);

void *__pthread_tsd_main[PTHREAD_KEYS_MAX] = { 0 };
static struct hmapi_thread_local_storage main_tls;

void __libc_init_tls()
{
	static int tls_inited;
	if (tls_inited)
		return;
	init_tls(&main_tls);
	if (memset_s(&pthread_main, sizeof(struct pthread), 0,
			 sizeof(struct pthread))) {
		hm_panic("memset_s failed\n");
	}
	pthread_main.robust_list.head = __convert2uint64(
						&pthread_main.robust_list.head);
	main_tls.thread_ptr = &pthread_main;
	pthread_main.tid = thread_tid();
	pthread_main.tsd = __pthread_tsd_main;
	tls_inited = 1; // mean true
}

/* This needs to be replaced by a better formal __libc_start_main */
int __libc_start_main(int argc, char *argv[], char *envp[])
{
	libc.page_size = 4096;
	__libc_init_tls();
#ifndef USE_IN_SYSMGR
	_init();
#endif
	hm_debug("<libc_start_main> run main with pthread struct %p\n", &pthread_main);
	int ret = main(argc, argv, envp);
	__funcs_on_exit();
#ifndef USE_IN_SYSMGR
	_fini();
#endif
	return ret;
}

/*
 * called by crt0_arm32/64.S. the fist c function of process(except boot apps).
 * p[3] = {argv ptr, envp ptr, paratbl ptr}. see details at function process_argv_inject.
 */
__attribute__((noreturn))
void __libc_start_hm(size_t *p)
{
	int argc = (int)((p[START_ARGS_ENVP] - p[START_ARGS_ARGV]) / sizeof(void *)) - 1;
	char **argv = (void *)(uintptr_t)p[START_ARGS_ARGV];
	char **envp = (void *)(uintptr_t)p[START_ARGS_ENVP];
	size_t *paratbl = (void *)(uintptr_t)p[START_ARGS_PARATBL];
	environ = envp;
#ifdef CONFIG_CC_STACKPROTECTOR
	__stack_chk_guard = paratbl[PARA_RANDOM];
#endif
#ifdef __LP64__
	__tcb_cref.tcb = paratbl[PARA_TCB_CREF];
	__sysmgrch = paratbl[PARA_SYSMGR_CREF];
#else
	/* Little-endian */
	__tcb_cref.tcb = ((uint64_t)paratbl[MODEL32_TCB_REF_HIG] << 32) | paratbl[MODEL32_TCB_REF_LOW];
	__sysmgrch = pthread_get_sysmgrch();
#endif
	hm_mmgr_clt_init();
	/* can not call hm_exit before cs_client_init */
	struct cs_client *sysmgr_client = get_sysmgr_client();
	if (sysmgr_client == NULL)
		hm_panic("hmstart: get sysmgr client failed\n");

	if (cs_client_init(sysmgr_client, __sysmgrch))
		hm_panic("hmstart: cs_client_init failed\n");
	hm_exit(__libc_start_main(argc, argv, envp));
	while (true)
		thread_exit(NULL);
	__builtin_unreachable();
}

static unsigned char buf[BUFSIZ + UNGET];

static void __reset_stdin(void)
{
	/* don't care the return value, and cannot call print here */
	(void)memset_s(&__stdin_FILE, sizeof(__stdin_FILE), 0, sizeof(__stdin_FILE));

	__stdin_FILE.buf = buf + UNGET;
	__stdin_FILE.buf_size = sizeof(buf) - UNGET;
	__stdin_FILE.flags = F_PERM | F_NOWR;
	__stdin_FILE.read = __stdio_read;
	__stdin_FILE.seek = __stdio_seek;
	__stdin_FILE.close = __stdio_close;
	__stdin_FILE.lock = -1;
}

static void __reset_stdout(void)
{
	/* we don't care the return value, and cannot call print here */
	(void)memset_s(&__stdout_FILE, sizeof(__stdout_FILE), 0, sizeof(__stdout_FILE));

	__stdout_FILE.buf = buf + UNGET;
	__stdout_FILE.buf_size = sizeof(buf) - UNGET;
	__stdout_FILE.fd = 1;
	__stdout_FILE.flags = F_PERM | F_NORD;
	__stdout_FILE.lbf = '\n';
	__stdout_FILE.write = __stdout_write;
	__stdout_FILE.seek = __stdio_seek;
	__stdout_FILE.close = __stdio_close;
	__stdout_FILE.lock = -1;
}

int __libc_pthread_reinit(void)
{
	hmapi_tls_init(&main_tls);
	// the pointers embedded in stdin & stdout need relocation
	__reset_stdin();
	__reset_stdout();

	// memory manager not initialized, unable to use malloc
	int c = memset_s(&pthread_main, sizeof(struct pthread), 0,
			 sizeof(struct pthread));
	if (c != 0) {
		return EINVAL;
	}
	pthread_main.robust_list.head = __convert2uint64(
						&pthread_main.robust_list.head);
	hmapi_tls_get()->thread_ptr = &pthread_main;
	pthread_main.tid = thread_tid();
	pthread_main.tsd = __pthread_tsd_main;
	return 0;
}
