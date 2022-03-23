/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: klad basic function impl.
 * Author: sdk team
 * Create: 2020-05-13
 */

#include "tee_klad_mgmt.h"

#include "tee_klad_utils.h"
#include "tee_klad_syscall.h"
#include "tee_klad_func.h"

static hi_s32 __klad_instance_find(hi_handle handle, struct klad_slot_instance **instance);

/*
 * API : klad_slot management defination.
 */
hi_s32 klad_slot_mgmt_init(hi_void)
{
    struct klad_slot_mgmt *mgmt = __get_klad_slot_mgmt();

    return mgmt->ops->init(mgmt);
}

hi_void klad_slot_mgmt_exit(hi_void)
{
    struct klad_slot_mgmt *mgmt = __get_klad_slot_mgmt();

    if (mgmt->ops->exit(mgmt) != HI_SUCCESS) {
        /*
         * must release all resource.
         */
        hi_fatal_klad("klad mgmt exit with error!\n");
    }
}

hi_s32 klad_slot_mgmt_create_slot(hi_handle *handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->create_slot(mgmt, handle);
}

hi_s32 klad_slot_mgmt_destroy_slot(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->destroy_slot(mgmt, handle);
}

hi_s32 klad_slot_mgmt_create_instance(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->create_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_destroy_instance(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->destroy_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_attach_ks(hi_handle handle, hi_handle handle_ks)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->attach_ks(mgmt, handle, handle_ks);
}

hi_s32 klad_slot_mgmt_detach_ks(hi_handle handle, hi_handle handle_ks)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->detach_ks(mgmt, handle, handle_ks);
}

hi_s32 klad_slot_mgmt_com_init(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->init_com_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_ta_init(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->init_ta_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_fp_init(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->init_fp_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_nonce_init(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->init_nonce_instance(mgmt, handle);
}

hi_s32 klad_slot_mgmt_clr_init(hi_handle handle)
{
    struct klad_slot_mgmt *mgmt = get_klad_slot_mgmt();

    return mgmt->ops->init_clr_instance(mgmt, handle);
}

hi_s32 klad_slot_get_klad_type(hi_handle handle, hi_u32 *klad_type)
{
    hi_s32 ret;
    struct klad_sw_base *base = HI_NULL_PTR;

    if (klad_type == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = klad_sw_r_get(handle, &base);
    if (ret == HI_SUCCESS) {
        *klad_type = base->klad_type;
    }
    return ret;
}

static hi_s32 __klad_slot_attach_impl(hi_handle *dst_handle, atomic64_t *cnt_ref,  hi_handle src_handle)
{
    if (*dst_handle == HI_INVALID_HANDLE || *dst_handle == 0) {
        *dst_handle = src_handle;
    } else {
        return HI_FAILURE;
    }
    atomic64_inc(cnt_ref);
    return HI_SUCCESS;
}

static hi_s32 __klad_slot_detach_impl(hi_handle *dst_handle,  hi_handle src_handle)
{
    if (*dst_handle == src_handle) {
        *dst_handle = HI_INVALID_HANDLE;
    } else {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}


/*
 *  ==================keyaldder software slot management defination.=========================
 * 1: define the methods of klad_slot management.
 *    create keyladder slot and destroy keyladder slot.
 */
static hi_s32 __klad_slot_mgmt_init_impl(struct klad_slot_mgmt *mgmt)
{
    warn_on(0 != atomic_read(&mgmt->ref_count));
    warn_on(mgmt->state != KLAD_SLOT_MGMT_CLOSED);

    mutex_init(&mgmt->slot_lock);
    init_list_head(&mgmt->slot_head);
    init_list_head(&mgmt->slot_empty_head);

    mgmt->state = KLAD_SLOT_MGMT_OPENED;

    return HI_SUCCESS;
}

static hi_s32 klad_slot_mgmt_init_impl(struct klad_slot_mgmt *mgmt)
{
    hi_s32 ret = HI_FAILURE;

    mutex_lock(&mgmt->lock);

    if (mgmt->state == KLAD_SLOT_MGMT_CLOSED) {
        ret = __klad_slot_mgmt_init_impl(mgmt);
        if (ret == HI_SUCCESS) {
            atomic_inc(&mgmt->ref_count);
        }
    } else if (mgmt->state == KLAD_SLOT_MGMT_OPENED) {
        warn_on(atomic_read(&mgmt->ref_count) == 0);

        atomic_inc(&mgmt->ref_count);

        ret = HI_SUCCESS;
    } else {
        hi_fatal_klad("mgmt state unknown, mgmt state is:%u\n", mgmt->state);
    }

    mutex_unlock(&mgmt->lock);

    return ret;
}

static hi_s32 __klad_slot_mgmt_exit_impl(struct klad_slot_mgmt *mgmt)
{
    struct klad_slot_instance *entry = HI_NULL;
    struct list_head *node_p = HI_NULL;
    struct list_head *tmp_node_p = HI_NULL;

    mutex_lock(&mgmt->slot_lock);

    list_for_each_safe(node_p, tmp_node_p, &mgmt->slot_empty_head) {
        entry = (struct klad_slot_instance *)list_entry(node_p, struct klad_sw_base, node);
        list_del(&((struct klad_sw_base *)entry)->node);
        hi_free(entry);
        entry = HI_NULL;
    }

    mutex_unlock(&mgmt->slot_lock);
    return HI_SUCCESS;
}

static hi_s32 _klad_slot_mgmt_exit_impl(struct klad_slot_mgmt *mgmt)
{
    hi_s32 ret = HI_FAILURE;

    if (mgmt->state == KLAD_SLOT_MGMT_OPENED) {
        warn_on(atomic_read(&mgmt->ref_count) == 0);

        if (atomic_read(&mgmt->ref_count) == 1) {
            ret = __klad_slot_mgmt_exit_impl(mgmt);
            if (ret == HI_SUCCESS) {
                atomic_dec(&mgmt->ref_count);
                mgmt->state = KLAD_SLOT_MGMT_CLOSED;
            }
        } else {
            atomic_dec(&mgmt->ref_count);

            ret = HI_SUCCESS;
        }
    } else if (mgmt->state == KLAD_SLOT_MGMT_CLOSED) {
        warn_on(atomic_read(&mgmt->ref_count));

        ret = HI_SUCCESS;
    } else {
        hi_fatal_klad("mgmt state unknown, mgmt state is:%u\n", mgmt->state);
    }
    return ret;
}

#define TEN_MSECS 10
#define LOOP_MAX 100
static hi_s32 klad_slot_mgmt_exit_impl(struct klad_slot_mgmt *mgmt)
{
    hi_s32 ret = HI_FAILURE;
    hi_u32 cnt = 0;

    do {
        mutex_lock(&mgmt->lock);

        ret = _klad_slot_mgmt_exit_impl(mgmt);

        mutex_unlock(&mgmt->lock);

        msleep(TEN_MSECS);
    } while (ret != HI_SUCCESS && (cnt++ < LOOP_MAX));

    return ret;
}

static hi_s32 klad_slot_mgmt_create_slot_impl(struct klad_slot_mgmt *mgmt, hi_handle *handle)
{
    hi_s32 ret;
    struct klad_slot *new_slot = HI_NULL;

    mutex_lock(&mgmt->lock);

    if (mgmt->state != KLAD_SLOT_MGMT_OPENED) {
        hi_err_klad("mgmt has not opened.\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = klad_slot_create(&new_slot);
    if (ret == HI_SUCCESS) {
        hi_dbg_klad("klad slot create succefull.\n");
        *handle = new_slot->handle;
    }
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_s32 klad_slot_mgmt_destroy_slot_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot *slot = HI_NULL;

    mutex_lock(&mgmt->lock);

    if (mgmt->state != KLAD_SLOT_MGMT_OPENED) {
        hi_err_klad("mgmt has not opened.\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = klad_slot_find(handle, &slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }

    ret = klad_slot_destroy(slot);
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_s32 __klad_slot_mgmt_instance_create_impl(struct klad_slot_mgmt *mgmt, struct klad_slot_instance **slot_inst)
{
    hi_s32 ret = HI_SUCCESS;
    struct klad_slot_instance *entry = HI_NULL_PTR;
    struct list_head *node = HI_NULL_PTR;

    mutex_lock(&mgmt->slot_lock);

    if (!list_empty(&mgmt->slot_empty_head)) {
        entry = (struct klad_slot_instance *)list_first_entry(&mgmt->slot_empty_head, struct klad_sw_base, node);
        list_del(&((struct klad_sw_base *)entry)->node);
    } else {
        entry = hi_malloc(sizeof(struct klad_slot_instance));
        if (entry == HI_NULL) {
            ret = HI_ERR_KLAD_NO_MEMORY;
            goto out;
        }
    }

    if (memset_s(entry, sizeof(struct klad_slot_instance), 0, sizeof(*entry)) != EOK) {
        hi_free(entry);
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }

    node = &((struct klad_sw_base *)entry)->node;

    init_list_head(node);
    list_add_tail(node, &mgmt->slot_head);
    *slot_inst = entry;
out:
    mutex_unlock(&mgmt->slot_lock);

    return ret;
}

static hi_s32 klad_slot_mgmt_instance_create_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *new_instance = HI_NULL;

    mutex_lock(&mgmt->lock);

    if (mgmt->state != KLAD_SLOT_MGMT_OPENED) {
        hi_err_klad("mgmt has not opened.\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = __klad_slot_mgmt_instance_create_impl(mgmt, &new_instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }

    ret = klad_slot_bind(handle, (struct klad_sw_base *)new_instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_s32 __klad_slot_mgmt_instance_destroy_impl(struct klad_slot_mgmt *mgmt, struct klad_slot *slot)
{
    hi_s32 ret = HI_SUCCESS;

    mutex_lock(&slot->lock);

    mutex_lock(&mgmt->slot_lock);

    list_del(&slot->obj->node);

    list_add_tail(&slot->obj->node, &mgmt->slot_empty_head);

    mutex_unlock(&mgmt->slot_lock);

    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_mgmt_instance_destroy_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot *slot = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = klad_slot_find(handle, &slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = __klad_slot_mgmt_instance_destroy_impl(mgmt, slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_s32 __klad_slot_mgmt_attach_ks_impl(struct klad_slot_mgmt *mgmt, struct klad_slot *slot, hi_handle handle_ks)
{
    hi_s32 ret;

    mutex_lock(&slot->lock);

    if (atomic_read(&slot->obj->ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }
    ret = __klad_slot_attach_impl(&slot->obj->target_handle, &slot->obj->target_cnt, handle_ks);

out:
    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_mgmt_attach_ks_impl(struct klad_slot_mgmt *mgmt, hi_handle handle, hi_handle handle_ks)
{
    hi_s32 ret;
    struct klad_slot *slot = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = klad_slot_find(handle, &slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = __klad_slot_mgmt_attach_ks_impl(mgmt, slot, handle_ks);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_s32 __klad_slot_mgmt_detach_ks_impl(struct klad_slot_mgmt *mgmt, struct klad_slot *slot, hi_handle handle_ks)
{
    hi_s32 ret;

    mutex_lock(&slot->lock);

    if (atomic_read(&slot->obj->ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }
    ret = __klad_slot_detach_impl(&slot->obj->target_handle, handle_ks);
out:
    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_mgmt_detach_ks_impl(struct klad_slot_mgmt *mgmt, hi_handle handle, hi_handle handle_ks)
{
    hi_s32 ret;
    struct klad_slot *slot = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = klad_slot_find(handle, &slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = __klad_slot_mgmt_detach_ks_impl(mgmt, slot, handle_ks);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}


static hi_s32 __klad_instance_find(hi_handle handle, struct klad_slot_instance **instance)
{
    hi_s32 ret;
    struct klad_slot *slot = HI_NULL;

    ret = klad_slot_find(handle, &slot);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    if (slot->obj != HI_NULL) {
        *instance = (struct klad_slot_instance *)(slot->obj);
    } else {
        hi_err_klad("not found.\n");
        return HI_ERR_KLAD_NOT_FIND_KLAD;
    }
out:
    return ret;
}

static hi_void __klad_slot_mgnt_instance_base_init_impl(struct klad_slot_mgmt *mgmt,
    struct klad_sw_base *base, hi_u32 klad_type)
{
    atomic_set(&base->ref_count, 1);
    atomic_set(&base->ref_async, 0);
    base->ops       = get_klad_sw_base_ops();
    base->release   = HI_NULL;
    base->mgmt      = mgmt;
    base->klad_type = klad_type;
    base->hw_handle = HI_INVALID_HANDLE;
}

static hi_void __klad_slot_mgmt_instance_clr_init_impl(struct klad_slot_mgmt *mgmt, struct clr_route_slot *instance)
{
    __klad_slot_mgnt_instance_base_init_impl(mgmt, &instance->base, HI_KLAD_CLR);

    mutex_init(&instance->lock);
    instance->ops = get_sw_clr_route_slot_ops();

    atomic64_set(&instance->attr_cnt, 0);
    atomic64_set(&instance->clr_cnt, 0);

    return;
}

static hi_s32 klad_slot_mgmt_instance_clr_init_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *instance  = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    if (instance->initialzed == HI_TRUE) {
        ret = HI_SUCCESS;
        goto out;
    }
    instance->klad = HI_KLAD_CLR;
    __klad_slot_mgmt_instance_clr_init_impl(mgmt, &instance->obj.clr_slot);
    instance->initialzed = HI_TRUE;

    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_void __klad_slot_mgmt_instance_nonce_init_impl(struct klad_slot_mgmt *mgmt, struct nonce_klad_slot *instance)
{
    hi_s32 i;

    __klad_slot_mgnt_instance_base_init_impl(mgmt, &instance->base, HI_KLAD_NONCE);

    mutex_init(&instance->lock);
    instance->ops = get_sw_nonce_klad_slot_ops();

    atomic64_set(&instance->attr_cnt, 0);
    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        atomic64_set(&instance->session_cnt[i], 0);
    }

    atomic64_set(&instance->nonce_cnt, 0);

    return;
}

static hi_s32 klad_slot_mgmt_instance_nonce_init_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *instance  = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    if (instance->initialzed == HI_TRUE) {
        ret = HI_SUCCESS;
        goto out;
    }
    instance->klad = HI_KLAD_NONCE;
    __klad_slot_mgmt_instance_nonce_init_impl(mgmt, &instance->obj.nonce_slot);
    instance->initialzed = HI_TRUE;

    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_void __klad_slot_mgmt_instance_ta_init_impl(struct klad_slot_mgmt *mgmt, struct ta_klad_slot *instance)
{
    __klad_slot_mgnt_instance_base_init_impl(mgmt, &instance->base, HI_KLAD_TA);

    mutex_init(&instance->lock);
    instance->ops = get_sw_ta_klad_slot_ops();

    atomic64_set(&instance->attr_cnt, 0);
    atomic64_set(&instance->session_ta_cnt, 0);
    atomic64_set(&instance->trans_cnt, 0);
    atomic64_set(&instance->trans_cnt, 0);

    return;
}

static hi_s32 klad_slot_mgmt_instance_ta_init_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *instance  = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    if (instance->initialzed == HI_TRUE) {
        ret = HI_SUCCESS;
        goto out;
    }
    instance->klad = HI_KLAD_TA;
    __klad_slot_mgmt_instance_ta_init_impl(mgmt, &instance->obj.ta_slot);
    instance->initialzed = HI_TRUE;

    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_void __klad_slot_mgmt_instance_fp_init_impl(struct klad_slot_mgmt *mgmt, struct fp_klad_slot *instance)
{
    hi_s32 i;

    __klad_slot_mgnt_instance_base_init_impl(mgmt, &instance->base, HI_KLAD_FP);

    mutex_init(&instance->lock);
    instance->ops = get_sw_fp_klad_slot_ops();

    atomic64_set(&instance->attr_cnt, 0);
    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        atomic64_set(&instance->session_cnt[i], 0);
    }

    atomic64_set(&instance->fp_cnt, 0);

    return;
}

static hi_s32 klad_slot_mgmt_instance_fp_init_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *instance  = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }
    if (instance->initialzed == HI_TRUE) {
        ret = HI_SUCCESS;
        goto out;
    }
    instance->klad = HI_KLAD_FP;
    __klad_slot_mgmt_instance_fp_init_impl(mgmt, &instance->obj.fp_slot);
    instance->initialzed = HI_TRUE;

    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static hi_void __klad_slot_mgmt_instance_com_init_impl(struct klad_slot_mgmt *mgmt, struct com_klad_slot *instance)
{
    hi_s32 i;

    __klad_slot_mgnt_instance_base_init_impl(mgmt, &instance->base, HI_KLAD_COM);

    mutex_init(&instance->lock);
    instance->ops = get_sw_com_klad_slot_ops();

    atomic64_set(&instance->rk_attr_cnt, 0);
    atomic64_set(&instance->attr_cnt, 0);
    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        atomic64_set(&instance->session_cnt[i], 0);
    }

    atomic64_set(&instance->content_cnt, 0);
    return;
}

static hi_s32 klad_slot_mgmt_instance_com_init_impl(struct klad_slot_mgmt *mgmt, hi_handle handle)
{
    hi_s32 ret;
    struct klad_slot_instance *instance = HI_NULL;

    mutex_lock(&mgmt->lock);

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        goto out;
    }

    if (instance->initialzed == HI_TRUE) {
        ret = HI_SUCCESS;
        goto out;
    }

    instance->klad = HI_KLAD_COM;
    __klad_slot_mgmt_instance_com_init_impl(mgmt, &instance->obj.com_slot);
    instance->initialzed = HI_TRUE;
    ret = HI_SUCCESS;
out:
    mutex_unlock(&mgmt->lock);
    return ret;
}

static struct klad_slot_mgmt_ops g_klad_slot_mgmt_ops = {
    .init                      = klad_slot_mgmt_init_impl,
    .exit                      = klad_slot_mgmt_exit_impl,

    .create_slot               = klad_slot_mgmt_create_slot_impl,
    .destroy_slot              = klad_slot_mgmt_destroy_slot_impl,

    .create_instance           = klad_slot_mgmt_instance_create_impl,
    .destroy_instance          = klad_slot_mgmt_instance_destroy_impl,

    .attach_ks                 = klad_slot_mgmt_attach_ks_impl,
    .detach_ks                 = klad_slot_mgmt_detach_ks_impl,

    .init_com_instance         = klad_slot_mgmt_instance_com_init_impl,
    .init_fp_instance          = klad_slot_mgmt_instance_fp_init_impl,
    .init_ta_instance          = klad_slot_mgmt_instance_ta_init_impl,
    .init_nonce_instance       = klad_slot_mgmt_instance_nonce_init_impl,
    .init_clr_instance         = klad_slot_mgmt_instance_clr_init_impl,
};

static struct klad_slot_mgmt g_klad_slot_mgmt = {
    .lock      = PTHREAD_MUTEX_INITIALIZER,
    .ref_count  = 0,
    .state     = KLAD_SLOT_MGMT_CLOSED,
    .ops       = &g_klad_slot_mgmt_ops,
};

struct klad_slot_mgmt *__get_klad_slot_mgmt(hi_void)
{
    return &g_klad_slot_mgmt;
}

/*
 * it needs to be guaranteed that software keyladder slot management has inited here.
 */
struct klad_slot_mgmt *get_klad_slot_mgmt(hi_void)
{
    struct klad_slot_mgmt *mgmt = __get_klad_slot_mgmt();

    warn_on(atomic_read(&mgmt->ref_count) == 0);

    return mgmt;
}
