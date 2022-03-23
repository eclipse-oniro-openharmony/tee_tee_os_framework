/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: keyladder session node list manage.
 * Author: Hisilicon hisecurity team
 * Create: 2019-6-25
 */
#include "tee_klad_syscall.h"

#include "posix_types.h"
#include "tee_klad_msg_queue.h"
#include "tee_klad_func.h"
#include "tee_klad_mgmt.h"

static struct klad_initial g_klad_initial = {
    .lock      = PTHREAD_MUTEX_INITIALIZER,
    .ref_count = 0,
    .thread_stop = HI_FALSE,
    .thread_once_hd = PTHREAD_ONCE_INIT,

    .thread_hd = 0,
};

hi_void get_time(struct time_ns *time)
{
//  TEE_Timestamp ts = {0};
    struct tee_time_stamp ts = {0};
    if (time == HI_NULL) {
        return;
    }

	uint32_t ret;
	ret = SRE_ReadTimestamp();
    if (ret == 0) {
        return;
    }

	time->tv_sec = ts.seconds;
    time->tv_nsec = ts.nanos;
}

hi_void get_cost(const hi_char *str, const struct time_ns *time_b, const struct time_ns *time_e)
{
    if (time_b == HI_NULL || time_e == HI_NULL) {
        return;
    }

    if (time_b->tv_sec ==  time_e->tv_sec) {
        hi_dbg_klad("%ld.%09ld ns-->%ld.%09ld ns, cost:%ld.%ld ms <<%s\n",
                    time_b->tv_sec, time_b->tv_nsec, time_e->tv_sec, time_e->tv_nsec,
                    (time_e->tv_nsec - time_b->tv_nsec) / TIME_MS2NS,
                    (time_e->tv_nsec - time_b->tv_nsec) % TIME_MS2NS,
                    str);
    } else {
        hi_dbg_klad("%ld.%09ld ns-->%ld.%09ld ns, cost:%ld.%ld ms <<%s\n",
                    time_b->tv_sec, time_b->tv_nsec, time_e->tv_sec, time_e->tv_nsec,
                    ((time_e->tv_sec - time_b->tv_sec) * TIME_S2NS + time_e->tv_nsec - time_b->tv_nsec) / TIME_MS2NS,
                    ((time_e->tv_sec - time_b->tv_sec) * TIME_S2NS + time_e->tv_nsec - time_b->tv_nsec) % TIME_MS2NS,
                    str);
    }
}

hi_void get_curr_cost(const hi_char *str, const struct time_ns *time_b)
{
    struct time_ns time_e;

    if (time_b == HI_NULL || str == HI_NULL) {
        return;
    }

    get_time(&time_e);
    get_cost(str, time_b, &time_e);
}

struct klad_initial *__get_klad_initial(hi_void)
{
    return &g_klad_initial;
}

static hi_s32 __klad_ioctl(unsigned int cmd, hi_void *data)
{
    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)data,
    };
    return hm_drv_call(CMD_KLAD_PROCESS, args, ARRAY_SIZE(args));
}

static hi_void mq_com_klad_asynchronize_impl(mq_data *data, struct com_klad_slot *slot)
{
    hi_s32 ret;
    struct time_ns time_b;

    /* If HW keyladder has created, start keyladder directly. */
    ret = klad_slot_com_create_impl(slot);
    if (ret != HI_SUCCESS && ret != HI_ERR_KLAD_HAVE_CREATED) {
        print_err_func(klad_slot_com_create_impl, ret);
        goto out;
    }
    get_time(&time_b);
    ret = klad_slot_com_start_impl(slot);
    get_curr_cost("com ioctl", &time_b);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_com_start_impl, ret);
    }
out:
    atomic_dec(&slot->base.ref_async);
    data->call_back_func(ret, HI_NULL, 0, data->user_data, data->user_data_len);
    return;
}

hi_void mq_klad_msgq(hi_void *args)
{
    mq_data buf = {0};
    mq_data *data = &buf;

    struct klad_initial *initial = __get_klad_initial();
    struct com_klad_slot *slot = HI_NULL_PTR;

    if (args == HI_NULL) {
        return;
    }

    hi_dbg_klad("mq_com_klad_msgq\n");
    while (initial->thread_stop == HI_FALSE) {
        mq_resv(data, sizeof(mq_data));

        klad_print_param((hi_char *)data, sizeof(mq_data));

        hi_dbg_klad("SERVER resv %p--scene:%d klad:%d len:%d. func:%p\n",
                    data, data->scene, data->type, data->len, data->call_back_func);

        if (data->type == MSG_TYPE_EXIT) {
            hi_dbg_klad("msg exit.\n");
            return;
        }

        if (data->len != sizeof(struct com_klad_slot)) {
            hi_err_klad("err length\n");
            continue;
        }

        slot = (struct com_klad_slot *)(data->msg);

        mq_com_klad_asynchronize_impl(data, slot);
    }
    return;
}

hi_s32 ctl_klad_init(hi_void)
{
    hi_s32 ret;
    struct klad_initial *initial = __get_klad_initial();

    klad_func_enter();
    mutex_lock(&initial->lock);

    if (atomic_read(&initial->ref_count) > 0) {
        atomic_inc(&initial->ref_count);
        ret = HI_SUCCESS;
        goto out;
    }

    ret = klad_slot_mgmt_init();
    if (ret != HI_SUCCESS) {
        goto out;
    }

    initial->thread_stop = HI_FALSE;
    ret = mq_create(sizeof(mq_data), QUEUE_POOL_MAX_DEPTH);
    if (ret != HI_SUCCESS) {
        goto mgmt_dinit;
    }
    atomic_set(&initial->ref_count, 1);

    mutex_unlock(&initial->lock);

    return HI_SUCCESS;

mgmt_dinit:
    klad_slot_mgmt_exit();

out:
    mutex_unlock(&initial->lock);

    klad_func_exit();
    return ret;
}

static hi_void __pthread_klad_destroy(hi_void)
{
    struct klad_initial *initial = __get_klad_initial();
    mq_data data = {0};

    initial->thread_stop = HI_TRUE;

    if (initial->thread_hd == 0) {
        return;
    }

    data.scene = ASYNCHRONIZE;
    data.type = MSG_TYPE_EXIT;

    mq_snd((char *)&data, sizeof(mq_data));

    pthread_join(initial->thread_hd, 0);
}

static hi_void __ctl_msgq_deinit(hi_void)
{
    __pthread_klad_destroy();

    mq_destroy();

    return;
}

hi_s32 ctl_klad_deinit(hi_void)
{
    struct klad_initial *initial = __get_klad_initial();

    klad_func_enter();

    mutex_lock(&initial->lock);

    if (atomic_read(&initial->ref_count) > 0) {
        atomic_dec(&initial->ref_count);
    }

    if (atomic_read(&initial->ref_count) != 0) {
        goto out;
    }
    klad_slot_mgmt_exit();
    __ctl_msgq_deinit();

    atomic_set(&initial->ref_count, -1);

out:
    mutex_unlock(&initial->lock);

    klad_func_exit();
    return HI_SUCCESS;
}

static hi_void __pthread_klad_create(hi_void)
{
    pthread_attr_t thread_attr = {0};
    struct klad_initial *initial = __get_klad_initial();

    pthread_attr_init(&thread_attr);

    pthread_attr_settee(&thread_attr, TEESMP_THREAD_ATTR_CA_INHERIT,
                        TEESMP_THREAD_ATTR_TASK_ID_INHERIT, TEESMP_THREAD_ATTR_HAS_SHADOW);

    pthread_create(&initial->thread_hd, &thread_attr, (void *)mq_klad_msgq, 0);

    return;
}

hi_void ctl_klad_msgq(hi_void)
{
    struct klad_initial *initial = __get_klad_initial();

    pthread_once(&initial->thread_once_hd, (void *)__pthread_klad_create);

    return;
}

hi_s32 ctl_klad_com_prepare(struct com_klad_slot *slot, hi_klad_com_entry *entry)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    hi_u32 i;

    if ((slot == HI_NULL) || (entry == HI_NULL)) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    entry->target_cnt = (hi_s64)atomic64_read(&slot->base.target_cnt);
    entry->target_handle = slot->base.target_handle;

    entry->rk_attr_cnt = (hi_s64)atomic64_read(&slot->rk_attr_cnt);
    if (memcpy_s(&entry->rk_attr, sizeof(entry->rk_attr), &slot->rk_attr, sizeof(hi_rootkey_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry->attr_cnt = (hi_s64)atomic64_read(&slot->attr_cnt);
    if (memcpy_s(&entry->attr, sizeof(entry->attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        entry->session_cnt[i] = (hi_s64)atomic64_read(&slot->session_cnt[i]);
        if (memcpy_s(&entry->session_key[i], sizeof(entry->session_key[i]),
                     &slot->session_key[i], sizeof(hi_klad_session_key)) != EOK) {
            print_err_func(memcpy_s, ret);
            goto out;
        }
    }

    entry->content_cnt = (hi_s64)atomic64_read(&slot->content_cnt);
    if (memcpy_s(&entry->content_key, sizeof(entry->content_key),
                 &slot->content_key, sizeof(hi_klad_content_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry->hw_handle = slot->base.hw_handle;
    ret = HI_SUCCESS;
out:
    return ret;
}

hi_s32 ctl_klad_com_attr_prepare(struct com_klad_slot *slot, hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;

    if ((slot == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    if (atomic64_read(&slot->attr_cnt) == 0) {
        print_err_hex2(atomic64_read(&slot->rk_attr_cnt), atomic64_read(&slot->attr_cnt));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    if (memcpy_s(&hkl_attr->rk_attr, sizeof(hkl_attr->rk_attr), &slot->rk_attr, sizeof(hi_rootkey_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    if (memcpy_s(&hkl_attr->attr, sizeof(hkl_attr->attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }
    hkl_attr->hw_handle = HI_INVALID_HANDLE;
    ret = HI_SUCCESS;
out:
    return ret;
}

hi_s32 ctl_klad_fp_attr_prepare(struct fp_klad_slot *slot, hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret = HI_SUCCESS;

    if ((slot == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    if (atomic64_read(&slot->attr_cnt) == 0) {
        print_err_hex(atomic64_read(&slot->attr_cnt));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    if (memcpy_s(&hkl_attr->attr, sizeof(hkl_attr->attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out;
    }
    hkl_attr->hw_handle = HI_INVALID_HANDLE;
out:
    return ret;
}

hi_s32 ctl_klad_com_startup(struct com_klad_slot *slot, const hi_klad_com_entry *entry)
{
    hi_s32 ret;

    if ((slot == HI_NULL) || (entry == HI_NULL)) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_ioctl(CMD_KLAD_COM_STARTUP, (hi_klad_com_entry *)entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_COM_STARTUP, ret);
        goto out;
    }
out:
    return ret;
}

hi_s32 ctl_klad_com_asynchronize_startup(struct com_klad_slot *slot, const klad_callback *call_back)
{
    mq_data data = {0};
    struct time_ns time_b;

    if (slot == HI_NULL || call_back == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    data.scene = ASYNCHRONIZE;
    data.type = MSG_TYPE_COM;
    data.call_back_func = call_back->call_back_func;
    data.user_data = call_back->user_data;
    data.user_data_len = call_back->user_data_len;
    data.msg = (hi_char *)slot;
    data.len = sizeof(struct com_klad_slot);

    get_time(&time_b);
    klad_print_param((char *)&data, sizeof(mq_data));
    mq_snd((char *)&data, sizeof(mq_data));
    atomic_inc(&slot->base.ref_async);

    get_curr_cost("send mq", &time_b);

    return HI_SUCCESS;
}

hi_s32 ctl_klad_ta_startup(struct ta_klad_slot *slot)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    hi_klad_ta_entry entry = {0};

    if (slot == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }
    entry.target_cnt = (hi_s64)atomic64_read(&slot->base.target_cnt);
    entry.target_handle = slot->base.target_handle;

    entry.attr_cnt = (hi_s64)atomic64_read(&slot->attr_cnt);
    if (memcpy_s(&entry.attr, sizeof(entry.attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.session_ta_cnt = (hi_s64)atomic64_read(&slot->session_ta_cnt);
    if (memcpy_s(&entry.session_ta_key, sizeof(entry.session_ta_key),
                 &slot->session_ta_key, sizeof(hi_klad_ta_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.trans_cnt = (hi_s64)atomic64_read(&slot->trans_cnt);
    if (memcpy_s(&entry.trans_data, sizeof(entry.trans_data), &slot->trans_data, sizeof(hi_klad_trans_data)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.session_ta_cnt = (hi_s64)atomic64_read(&slot->session_ta_cnt);
    if (memcpy_s(&entry.session_ta_key, sizeof(entry.session_ta_key),
                 &slot->session_ta_key, sizeof(hi_klad_ta_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.content_ta_cnt = (hi_s64)atomic64_read(&slot->content_ta_cnt);
    if (memcpy_s(&entry.content_ta_key, sizeof(entry.content_ta_key),
                 &slot->content_ta_key, sizeof(hi_klad_ta_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    ret = __klad_ioctl(CMD_KLAD_TA_STARTUP, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_TA_STARTUP, ret);
        goto out;
    }
    slot->base.hw_handle = entry.hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_fp_prepare(struct fp_klad_slot *slot, hi_klad_fp_entry *entry)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    hi_u32 i;

    if ((slot == HI_NULL) || (entry == HI_NULL)) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    entry->target_cnt = (hi_s64)atomic64_read(&slot->base.target_cnt);
    entry->target_handle = slot->base.target_handle;

    entry->attr_cnt = (hi_s64)atomic64_read(&slot->attr_cnt);
    if (memcpy_s(&entry->attr, sizeof(entry->attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }
    for (i = 0; i < HI_KLAD_LEVEL_MAX; i++) {
        entry->session_cnt[i] = (hi_s64)atomic64_read(&slot->session_cnt[i]);
        if (memcpy_s(&entry->session_key[i], sizeof(entry->session_key[i]),
                     &slot->session_key[i], sizeof(hi_klad_session_key)) != EOK) {
            print_err_func(memcpy_s, ret);
            goto out;
        }
    }
    entry->fp_cnt = (hi_s64)atomic64_read(&slot->fp_cnt);
    if (memcpy_s(&entry->fp_key, sizeof(entry->fp_key), &slot->fp_key, sizeof(hi_klad_fp_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry->hw_handle = slot->base.hw_handle;
    ret = HI_SUCCESS;
out:
    return ret;
}

hi_s32 ctl_klad_fp_startup(struct fp_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_fp_entry entry = {0};

    if (slot == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = ctl_klad_fp_prepare(slot, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_prepare, ret);
        goto out;
    }

    ret = __klad_ioctl(CMD_KLAD_FP_STARTUP, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_FP_STARTUP, ret);
        goto out;
    }
    slot->base.hw_handle = entry.hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_fp_crypto(struct fp_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_fp_entry entry = {0};

    if (slot == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = ctl_klad_fp_prepare(slot, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_prepare, ret);
        goto out;
    }

    ret = __klad_ioctl(CMD_KLAD_FP_CRYPTO, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_FP_CRYPTO, ret);
        goto out;
    }
    slot->base.hw_handle = entry.hw_handle;
    slot->fp_key.enc_key_size = entry.fp_key.enc_key_size;
    if (memcpy_s(slot->fp_key.enc_key, sizeof(slot->fp_key.enc_key),
                 entry.fp_key.enc_key, HI_KLAD_MAX_KEY_LEN) != EOK) {
        return HI_ERR_KLAD_SEC_FAILED;
    }
out:
    return ret;
}

hi_s32 ctl_klad_fp_route(struct fp_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_create_attr hkl_attr = {0};

    if (slot == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = ctl_klad_fp_attr_prepare(slot, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_attr_prepare, ret);
        goto out;
    }

    /*  add other prams */
    ret = __klad_ioctl(CMD_KLAD_FP_ROUTE, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_FP_ROUTE, ret);
        goto out;
    }

out:
    return ret;
}

hi_s32 ctl_klad_nonce_startup(struct nonce_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_nonce_entry entry = {0};

    if (slot == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }
    entry.target_cnt = (hi_s64)atomic64_read(&slot->base.target_cnt);
    entry.target_handle = slot->base.target_handle;

    /*  add other prams */
    ret = __klad_ioctl(CMD_KLAD_NONCE_STARTUP, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_NONCE_STARTUP, ret);
        goto out;
    }
    slot->base.hw_handle = entry.hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_clr_process(struct clr_route_slot *slot)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    hi_klad_clr_entry entry = {0};
    struct time_ns time_b;

    if (slot == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }
    entry.target_cnt = (hi_s64)atomic64_read(&slot->base.target_cnt);
    entry.target_handle = slot->base.target_handle;

    entry.attr_cnt = (hi_s64)atomic64_read(&slot->attr_cnt);
    if (memcpy_s(&entry.attr, sizeof(entry.attr), &slot->attr, sizeof(hi_klad_attr)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    entry.clr_cnt = (hi_s64)atomic64_read(&slot->clr_cnt);
    if (memcpy_s(&entry.clr_key, sizeof(entry.clr_key), &slot->clr_key, sizeof(hi_klad_clear_key)) != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }
    get_time(&time_b);

    ret = __klad_ioctl(CMD_KLAD_CLR_PROCESS, &entry);

    get_curr_cost("clr ioctl", &time_b);

    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_CLR_PROCESS, ret);
        goto out;
    }
    slot->base.hw_handle = entry.hw_handle;
out:
    return ret;
}


hi_s32 ctl_klad_com_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret;

    if ((handle == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    ret = __klad_ioctl(CMD_KLAD_COM_CREATE, (hi_klad_create_attr *)hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_COM_CREATE, ret);
        goto out;
    }
    *handle = hkl_attr->hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_ta_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret;

    if ((handle == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    ret = __klad_ioctl(CMD_KLAD_TA_CREATE, (hi_klad_create_attr *)hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_TA_CREATE, ret);
        goto out;
    }
    *handle = hkl_attr->hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_fp_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret;

    if ((handle == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    ret = __klad_ioctl(CMD_KLAD_FP_CREATE, (hi_klad_create_attr *)hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_FP_CREATE, ret);
        goto out;
    }
    *handle = hkl_attr->hw_handle;
out:
    return ret;
}

hi_s32 ctl_klad_nonce_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr)
{
    hi_s32 ret;

    if ((handle == HI_NULL) || (hkl_attr == HI_NULL)) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    ret = __klad_ioctl(CMD_KLAD_NONCE_CREATE, (hi_klad_create_attr *)hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_KLAD_NONCE_CREATE, ret);
        goto out;
    }
    *handle = hkl_attr->hw_handle;
out:
    return ret;
}


hi_s32 ctl_klad_com_destroy(hi_handle hw_handle)
{
    hi_s32 ret;
    hi_handle handle = hw_handle;

    ret = __klad_ioctl(CMD_KLAD_COM_DESTORY, &handle);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KLAD_COM_DESTORY, handle, ret);
        goto out;
    }
out:
    return ret;
}

hi_s32 ctl_klad_ta_destroy(hi_handle hw_handle)
{
    hi_s32 ret;
    hi_handle handle = hw_handle;

    ret = __klad_ioctl(CMD_KLAD_TA_DESTORY, &handle);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KLAD_TA_DESTORY, handle, ret);
        goto out;
    }
out:
    return ret;
}

hi_s32 ctl_klad_fp_destroy(hi_handle hw_handle)
{
    hi_s32 ret;
    hi_handle handle = hw_handle;

    ret = __klad_ioctl(CMD_KLAD_FP_DESTORY, &handle);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KLAD_FP_DESTORY, handle, ret);
        goto out;
    }
out:
    return ret;
}

hi_s32 ctl_klad_nonce_destroy(hi_handle hw_handle)
{
    hi_s32 ret;
    hi_handle handle = hw_handle;

    ret = __klad_ioctl(CMD_KLAD_NONCE_DESTORY, &handle);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KLAD_NONCE_DESTORY, handle, ret);
        goto out;
    }
out:
    return ret;
}



