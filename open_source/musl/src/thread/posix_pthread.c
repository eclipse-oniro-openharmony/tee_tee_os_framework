#define _POSIX_THREADS
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <securec.h>
#include "hm/thread.h"
#include "pthread_impl.h"
#include "sys/usrsyscall.h"
#include <hm_mman.h>
#include <uapi/priorities_kernel.h>
#include <sys/usrsyscall.h>
#include <hm_thread.h>
#include <mm_kcall.h>
#include <api/errno.h>
#include <hmlog.h>
#include "pthread_ext.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define ROUND(x) (((x) + PAGE_SIZE - 1) & -PAGE_SIZE)
#define MIN_STACKSIZE (PAGE_SIZE)

extern void __pthread_tsd_run_dtors();

pthread_t pthread_self()
{
	return (pthread_t)hmapi_tls_get()->thread_ptr;
}


int pthread_create(pthread_t *thread, const pthread_attr_t *thread_attr,
		   void *(*start_routine)(void *), void *arg)
{
	int c;
	int ret;
	int c11 = (thread_attr == __ATTRP_C11_THREAD);
	size_t guard = 0;
	size_t size = 0;
	size_t stack_size = 0;
	pthread_attr_t attr;
	unsigned char *tsd = NULL;
	unsigned char *map = NULL;
	unsigned char *stack = NULL;
	if (thread == NULL || start_routine == NULL)
		return EINVAL;

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		goto err;
	}
	if (thread_attr && !c11) {
		// Don't use  `attr = *thread_attr;`
		// As other libc pthread_attr_t may be less than musl pthread_attr_t size;
		__pthread_attr_copy(&attr, (pthread_attr_t *)thread_attr);
	}

	// thread stack:
	//
	//    _________   <---- stack bottom
	//   |         |
	//   |  thread |
	//   |  stack  |
	//   |_________|  <-  stack start (sta[M D'rt sp pointer) & struct pthread pointer
	//   |         |
	//   | struct  |
	//   | pthread |   struct pthread structure.
	//   |_________|
	//   |         |
	//   | tls data|  <-- tls data if supported.(now its size is zero, not supported yet)
	//   |_________|  <-tsd
	//   |         |
	//   | tls spec|
	//   | keydata |
	//   |_________|  <------ pthread key sepcific data.
	if (attr._a_stacksize == 0) {
		attr._a_stacksize = DEFAULT_STACK_SIZE;
	}
	if (attr._a_guardsize == 0) {
		attr._a_guardsize = DEFAULT_GUARD_SIZE;
	}

	// prepare the thread stack
	if (attr._a_stackaddr) {
		size_t cost = __pthread_tsd_size + sizeof(struct pthread);
		ret = pthread_attr_getstack((const pthread_attr_t *)&attr, (void **)&stack,
					    &size);
		if (ret != 0)
			goto err;

		// try to use application-provided stack.
		// if application-provided stack size - psd size > MIN_STACKSIZE;
		// we could use this stack, or it is too small
		if (size > (MIN_STACKSIZE + cost)) {
			tsd = stack + size - __pthread_tsd_size;
			c = memset_s(stack, size, 0, size);
			if (c != 0) {
				ret = EINVAL;
				goto err;
			}
			unsigned char *tmp = (unsigned char *)(uintptr_t)(((uintptr_t)stack + 127) & ~127UL);
			stack_size = size - cost - (tmp - stack);
			stack_size &= ~127UL;
			stack = tmp;
		} else {
			// reset size to MIN_STACKSIZE+cost, then round up.
			size = ROUND(MIN_STACKSIZE + cost);
			guard = 0;
		}
	} else {
		guard = ROUND(attr._a_guardsize);
		size = ROUND(attr._a_stacksize + __pthread_tsd_size) + guard;
	}

	if (tsd == NULL) {
		// tsd not set, means:
		//   1. application don't provided stack
		//   2. application provide stack too small. we need to re-allocate the stack for thread.
		map = hm_mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
			      0);
		if (map == MAP_FAILED || map == NULL) {
			// if map==MAP_FAILED, do not unmap it.
			map = NULL;
			ret = errno;
			goto err;
		}
		if (guard) {
			if (mprotect(map, guard, PROT_NONE)) {
				// unmap map directly.
				guard = 0;
				ret = errno;
				goto err;
			}
			if (hm_muncommit(map, guard)) {
				ret = errno;
				goto err;
			}
		}
		c = memset_s(map + guard, size - guard, 0, size - guard);
		if (c != 0)
			goto err;
		// 1. setup tsd addr:
		tsd = map + size - __pthread_tsd_size;
		stack = (unsigned char *)(uintptr_t)(((uintptr_t)map + 127) & (~127UL));
		stack_size = size - (stack - map) - __pthread_tsd_size - sizeof(struct pthread);
		stack_size = (size_t)(stack_size & ~127UL);
	}

	struct pthread *new = (struct pthread *)(tsd - sizeof(struct pthread));
	// set tid to invalid number.
	new->tid = (uint64_t) -1;
	new->map_base = map;
	new->map_size = size;
	new->guard_size = guard;
	new->stack = stack + stack_size;
	new->stack_size = stack_size;

	// self pointer.
	new->self = new;
	// tsd, for pthread_key_setspecific()
	new->tsd = (void **)tsd;
	new->start = start_routine;
	new->start_arg = arg;
	new->robust_list.head = __convert2uint64(&new->robust_list.head);

	thread_attr_t th_attr;
	(void)thread_attr_init(&th_attr);
#ifdef CONFIG_ENABLE_TEESMP
	th_attr.ca = TEESMP_THREAD_ATTR_CA_INHERIT;
	th_attr.task_id = TEESMP_THREAD_ATTR_TASK_ID_INHERIT;
	// user set ca attr
	if ((unsigned)attr._a_ca != TEESMP_THREAD_ATTR_INVALID) {
		th_attr.ca = (uint32_t)attr._a_ca;
	}
	// user set task_id attr
	if ((unsigned)attr._a_task_id != TEESMP_THREAD_ATTR_INVALID) {
		th_attr.task_id = (uint32_t)attr._a_task_id;
	}
	if ((unsigned int)attr._a_flag & PTHREAD_ATTR_FLAG_SHADOW) {
		th_attr.flags |= TEESMP_THREAD_ATTR_F_SHADOW;
	}
#endif
	th_attr.stack_vaddr = (uintptr_t)stack;
	th_attr.stack_size = stack_size;
	a_inc(&libc.threads_minus_1);
	ret = thread_create((cref_t *)&new->cref, &th_attr, start_routine, new);
	if (ret != 0) {
		a_dec(&libc.threads_minus_1);
		goto err;
	}
	*thread = new;
	(void)pthread_attr_destroy(&attr);
	return 0;
err:
	// release attribute
	(void)pthread_attr_destroy(&attr);
	// release thread stack
	if (map != NULL) {
		if (guard) {
			if (hm_munmap(map, guard))
				hm_error("hm_munmap failed\n");
			if (hm_munmap(map + guard, size - guard))
				hm_error("hm_munmap failed\n");
		} else {
			if (hm_munmap(map, size))
				hm_error("hm_munmap failed\n");
		}
	}
	return ret;
}

extern void mutex_node_free(struct mutex_link * p);

_Noreturn void pthread_exit(void *result)
{
	struct pthread *self = __pthread_self();

	// thread exit value.
	self->result = result;

	// call cleanup functions which added by pthread_cleanup_push
	while (self->cancelbuf) {
		void (*f)(void *) = self->cancelbuf->__f;
		void *x = self->cancelbuf->__x;
		self->cancelbuf = self->cancelbuf->__next;
		f(x);
	}

	// call tsd destructors.
	__pthread_tsd_run_dtors();

	self->dead = 1;

	/* It's impossible to determine whether this is "the last thread"
	 * until performing the atomic decrement, since multiple threads
	 * could exit at the same time. For the last thread, revert the
	 * decrement to give the atexit handlers and stdio cleanup code
	 * a consistent state. */
	if (a_fetch_add(&libc.threads_minus_1, -1) == 0) {
		libc.threads_minus_1 = 0;
	}

	/* Process robust list in userspace to handle non-pshared mutexes
	 * and the detached thread case where the robust list head will
	 * be invalid when the kernel would process it. */
	__vm_lock();
	volatile void *volatile *rp = __convert2ptr(self->robust_list.head);
	for (; rp != NULL && rp != (void *)&self->robust_list.head;
		rp = __convert2ptr(self->robust_list.head)) {
		pthread_mutex_t *m = (void *)((char *)(((struct mutex_link *)rp)->m)
					      - offsetof(pthread_mutex_t, _m_lock));
		int waiters = m->_m_waiters;
		int priv = ((unsigned int)m->_m_type & 128) ^ 128;
		self->robust_list.pending = __convert2uint64((void *)rp);
		self->robust_list.head = __convert2uint64((void *)*rp);
		int cont = a_swap(&m->_m_lock, 0x40000000);
		self->robust_list.pending = 0;
		mutex_node_free((void *)rp);
		rp = NULL;
		m->_m_link = -1;
		if (cont < 0 || waiters)
			__wake(&m->_m_lock, 1, priv);
	}
	__vm_unlock();

	long rc;
	rc = __syscall(SYS_set_robust_list, 0, sizeof(self->robust_list));
	if (rc != E_EX_OK) {
		hm_panic("pthread_exit for syscall failed!!!\n");
	}

	if (self->detached && self->map_base != NULL) {
		//  thread in detach mode, do not call phtread_join in main thread.
		//       we need to cleanup all the garbage at pthread_exit.
		//
		// 1. We need call TCB_JOIN after thread_exit to free the 'zombie' thread.
		//    But thread_exit is a non-returned function, we don't have chance to call TCB_JOIN to kernel ourself.
		//
		// 2. Now we can not free the map_base, as the thread stack is in self->map_base, after free this,
		//    we do not have stack.(using asm functions instead of c function could solve this issue.)
		//
	}
	for (;;)
		thread_exit(NULL);
}

weak void heap_cleanup(int32_t tid)
{
}

int pthread_join(pthread_t t, void **res)
{
	if (t == NULL)
		return EINVAL;
	if (t->detached) a_crash();
	if (thread_join(t->cref, res))
		return EINVAL;
	heap_cleanup(t->tid);
	hm_delete_object(hm_get_mycnode(), t->cref);
	// after join, before free the stack, we get the thread exit code
	if (res != NULL)
		*res = t->result;
	if (t->map_base != NULL) {
		// free the stack allocated by hongmeng.
		if (t->guard_size) {
			if (hm_munmap(t->map_base, t->guard_size))
				hm_error("hm_munmap failed\n");
			if (hm_munmap(t->map_base + t->guard_size, t->map_size - t->guard_size))
				hm_error("hm_munmap failed\n");
		} else {
			if (hm_munmap(t->map_base, t->map_size))
				hm_error("hm_munmap failed\n");
		}
	}

	return 0;
}

void __do_cleanup_push(struct __ptcb *cb)
{
    if (cb != NULL) {
        struct pthread *self = __pthread_self();
        cb->__next = self->cancelbuf;
        self->cancelbuf = cb;
    } else {
        printf("invalid cleanup_push parameters\n");
    }
}

void __do_cleanup_pop(struct __ptcb *cb)
{
    if (cb != NULL)
        __pthread_self()->cancelbuf = cb->__next;
    else
        printf("invalid cleanup_pop parameters\n");
}

int pthread_detach(pthread_t t)
{
	if (t == NULL)
		return EINVAL;
	t->detached = 2;
	return 0;
}

int pthread_setschedprio(pthread_t t, int prio)
{
	if (prio > HM_PRIO_KERNEL_CAN_CONFIG_MAX ||
	    prio < HM_PRIO_KERNEL_CAN_CONFIG_MIN) {
		return EINVAL;
	}
	return set_thread_priority(t->cref, prio);
}

cref_t pthread_get_sysmgrch_np(pthread_t thread)
{
	return thread->cref;
}

pid_t gettid()
{
	pthread_t self = pthread_self();
	if (self != NULL && self->tid != (uint64_t)-1) {
		return self->tid;
	}
	return thread_tid();
}
