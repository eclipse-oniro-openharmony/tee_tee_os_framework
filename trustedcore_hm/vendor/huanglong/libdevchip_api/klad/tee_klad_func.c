/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: klad basic function impl.
 * Author: sdk team
 * Create: 2019-07-28
 */

#include "tee_klad_func.h"

#include "tee_klad_utils.h"
#include "tee_klad_syscall.h"
#include "tee_klad_mgmt.h"

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

/*
 * API : klad software instance defination.
 */
static struct klad_com_ops g_sw_com_klad_slot_ops;

static hi_s32 __klad_sw_r_com_get(hi_handle handle, struct com_klad_slot **com_klad)
{
    hi_s32 ret;
    ret = klad_sw_r_get(handle, (struct klad_sw_base **)com_klad);
    if (ret == HI_SUCCESS) {
        if (&g_sw_com_klad_slot_ops != (*com_klad)->ops) {
            klad_sw_r_put((struct klad_sw_base *)(*com_klad));
            ret = HI_ERR_KLAD_INVALID_PARAM;
        }
    }
    return ret;
}

hi_s32 klad_slot_com_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->set_attr(com_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->get_attr(com_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (rootkey == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->set_rootkey_attr(com_klad, rootkey);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (rootkey == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->get_rootkey_attr(com_klad, rootkey);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_set_session_key(hi_handle handle, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (session_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->set_session_key(com_klad, session_key);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_set_content_key(hi_handle handle, const hi_klad_content_key *content_key)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (content_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->set_content_key(com_klad, content_key);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_start(hi_handle handle)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->start(com_klad);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_async_start(hi_handle handle, const klad_callback *call_back)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    if (call_back == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->start_asynchronous(com_klad, call_back);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

hi_s32 klad_slot_com_stop(hi_handle handle)
{
    hi_s32 ret;
    struct com_klad_slot *com_klad = HI_NULL;

    ret = __klad_sw_r_com_get(handle, &com_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = com_klad->ops->stop(com_klad);

    klad_sw_r_put((struct klad_sw_base *)com_klad);
out0:
    return ret;
}

static struct klad_fp_ops g_sw_fp_klad_slot_ops;

static hi_s32 __klad_sw_r_fp_get(hi_handle handle, struct fp_klad_slot **fp_klad)
{
    hi_s32 ret;
    ret = klad_sw_r_get(handle, (struct klad_sw_base **)fp_klad);
    if (ret == HI_SUCCESS) {
        if (&g_sw_fp_klad_slot_ops != (*fp_klad)->ops) {
            klad_sw_r_put((struct klad_sw_base *)(*fp_klad));
            ret = HI_ERR_KLAD_INVALID_PARAM;
        }
    }
    return ret;
}

hi_s32 klad_slot_fp_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->set_attr(fp_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->get_attr(fp_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_set_session_key(hi_handle handle, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    if (session_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->set_session_key(fp_klad, session_key);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_set_fp_key(hi_handle handle, const hi_klad_fp_key *fp_key)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    if (fp_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->set_fp_key(fp_klad, fp_key);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_start(hi_handle handle)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->start(fp_klad);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_enc(hi_handle handle, hi_u8 *enc_key, hi_u32 enc_key_len)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    if (enc_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->crypto(fp_klad);
    if (memcpy_s(enc_key, enc_key_len, fp_klad->fp_key.enc_key, fp_klad->fp_key.enc_key_size) != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out0;
    }

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_route(hi_handle handle)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->route(fp_klad);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}

hi_s32 klad_slot_fp_stop(hi_handle handle)
{
    hi_s32 ret;
    struct fp_klad_slot *fp_klad = HI_NULL;

    ret = __klad_sw_r_fp_get(handle, &fp_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = fp_klad->ops->stop(fp_klad);

    klad_sw_r_put((struct klad_sw_base *)fp_klad);
out0:
    return ret;
}


static struct klad_ta_ops g_sw_ta_klad_slot_ops;

static hi_s32 __klad_sw_r_ta_get(hi_handle handle, struct ta_klad_slot **ta_klad)
{
    hi_s32 ret;
    ret = klad_sw_r_get(handle, (struct klad_sw_base **)ta_klad);
    if (ret == HI_SUCCESS) {
        if (&g_sw_ta_klad_slot_ops != (*ta_klad)->ops) {
            klad_sw_r_put((struct klad_sw_base *)(*ta_klad));
            ret = HI_ERR_KLAD_INVALID_PARAM;
        }
    }
    return ret;
}

hi_s32 klad_slot_ta_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->set_attr(ta_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->get_attr(ta_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_set_session_key(hi_handle handle, const hi_klad_ta_key *ta_key)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    if (ta_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->set_session_ta_key(ta_klad, ta_key);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_set_trans_data(hi_handle handle, const hi_klad_trans_data *trans_data)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    if (trans_data == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->set_trans_data(ta_klad, trans_data);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_set_content_key(hi_handle handle, const hi_klad_ta_key *ta_key)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    if (ta_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->set_content_ta_key(ta_klad, ta_key);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_start(hi_handle handle)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->start(ta_klad);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

hi_s32 klad_slot_ta_stop(hi_handle handle)
{
    hi_s32 ret;
    struct ta_klad_slot *ta_klad = HI_NULL;

    ret = __klad_sw_r_ta_get(handle, &ta_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = ta_klad->ops->stop(ta_klad);

    klad_sw_r_put((struct klad_sw_base *)ta_klad);
out0:
    return ret;
}

static struct klad_nonce_ops g_sw_nonce_klad_slot_ops;

static hi_s32 __klad_sw_r_nonce_get(hi_handle handle, struct nonce_klad_slot **nonce_klad)
{
    hi_s32 ret;
    ret = klad_sw_r_get(handle, (struct klad_sw_base **)nonce_klad);
    if (ret == HI_SUCCESS) {
        if (&g_sw_nonce_klad_slot_ops != (*nonce_klad)->ops) {
            klad_sw_r_put((struct klad_sw_base *)(*nonce_klad));
            ret = HI_ERR_KLAD_INVALID_PARAM;
        }
    }
    return ret;
}

hi_s32 klad_slot_nonce_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->set_attr(nonce_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

hi_s32 klad_slot_nonce_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->get_attr(nonce_klad, attr);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

hi_s32 klad_slot_nonce_set_session_key(hi_handle handle, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    if (session_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->set_session_key(nonce_klad, session_key);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

hi_s32 klad_slot_nonce_set_nonce_key(hi_handle handle, const hi_klad_nonce_key *nonce_key)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    if (nonce_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->set_nonce_key(nonce_klad, nonce_key);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

hi_s32 klad_slot_nonce_start(hi_handle handle)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->start(nonce_klad);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

hi_s32 klad_slot_nonce_stop(hi_handle handle)
{
    hi_s32 ret;
    struct nonce_klad_slot *nonce_klad = HI_NULL;

    ret = __klad_sw_r_nonce_get(handle, &nonce_klad);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = nonce_klad->ops->stop(nonce_klad);

    klad_sw_r_put((struct klad_sw_base *)nonce_klad);
out0:
    return ret;
}

static struct klad_clr_route_ops g_sw_clr_route_slot_ops;

static hi_s32 __klad_sw_r_clr_get(hi_handle handle, struct clr_route_slot **clr_route)
{
    hi_s32 ret;
    ret = klad_sw_r_get(handle, (struct klad_sw_base **)clr_route);
    if (ret == HI_SUCCESS) {
        if (&g_sw_clr_route_slot_ops != (*clr_route)->ops) {
            klad_sw_r_put((struct klad_sw_base *)(*clr_route));
            ret = HI_ERR_KLAD_INVALID_PARAM;
        }
    }
    return ret;
}

hi_s32 klad_slot_clr_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct clr_route_slot *clr_route = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_clr_get(handle, &clr_route);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = clr_route->ops->set_attr(clr_route, attr);

    klad_sw_r_put((struct klad_sw_base *)clr_route);
out0:
    return ret;
}

hi_s32 klad_slot_clr_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct clr_route_slot *clr_route = HI_NULL;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_clr_get(handle, &clr_route);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = clr_route->ops->get_attr(clr_route, attr);

    klad_sw_r_put((struct klad_sw_base *)clr_route);
out0:
    return ret;
}

hi_s32 klad_slot_clr_set_key(hi_handle handle, const hi_klad_clear_key *clr_key)
{
    hi_s32 ret;
    struct clr_route_slot *clr_route = HI_NULL;

    if (clr_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_sw_r_clr_get(handle, &clr_route);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = clr_route->ops->set_clr_key(clr_route, clr_key);

    klad_sw_r_put((struct klad_sw_base *)clr_route);
out0:
    return ret;
}

hi_s32 klad_slot_clr_start(hi_handle handle)
{
    hi_s32 ret;
    struct clr_route_slot *clr_route = HI_NULL;

    ret = __klad_sw_r_clr_get(handle, &clr_route);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = clr_route->ops->start(clr_route);

    klad_sw_r_put((struct klad_sw_base *)clr_route);
out0:
    return ret;
}

hi_s32 klad_slot_clr_stop(hi_handle handle)
{
    hi_s32 ret;
    struct clr_route_slot *clr_route = HI_NULL;

    ret = __klad_sw_r_clr_get(handle, &clr_route);
    if (ret != HI_SUCCESS) {
        goto out0;
    }

    ret = clr_route->ops->stop(clr_route);

    klad_sw_r_put((struct klad_sw_base *)clr_route);
out0:
    return ret;
}

static hi_s32 __klad_slot_type(hi_handle handle, hi_u32 *type)
{
    hi_s32 ret;
    struct klad_sw_base *base = HI_NULL;

    ret = klad_sw_r_get(handle, &base);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_sw_r_get, ret);
        goto out;
    }
    *type = base->klad_type;

    klad_sw_r_put(base);
out:
    return ret;
}

hi_s32 klad_slot_instance_init(hi_handle handle, hi_klad_type klad)
{
    if (klad == HI_KLAD_COM) {
        return klad_slot_mgmt_com_init(handle);
    } else if (klad == HI_KLAD_TA) {
        return klad_slot_mgmt_ta_init(handle);
    } else if (klad == HI_KLAD_FP) {
        return klad_slot_mgmt_fp_init(handle);
    } else if (klad == HI_KLAD_NONCE) {
        return klad_slot_mgmt_nonce_init(handle);
    } else if (klad == HI_KLAD_CLR) {
        return klad_slot_mgmt_clr_init(handle);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_bool klad_slot_instance_initialzed(hi_handle handle)
{
    hi_s32 ret;

    struct klad_slot_instance *instance  = HI_NULL;

    ret = __klad_instance_find(handle, &instance);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_instance_find, ret);
        return HI_FALSE;
    }
    if (instance->initialzed == HI_TRUE) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

hi_s32 klad_slot_instance_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_u8 klad;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    klad = get_klad_type(attr->klad_cfg.klad_type);
    if (klad == HI_KLAD_COM) {
        return klad_slot_com_set_attr(handle, attr);
    } else if (klad == HI_KLAD_TA) {
        return klad_slot_ta_set_attr(handle, attr);
    } else if (klad == HI_KLAD_FP) {
        return klad_slot_fp_set_attr(handle, attr);
    } else if (klad == HI_KLAD_NONCE) {
        return klad_slot_nonce_set_attr(handle, attr);
    } else if (klad == HI_KLAD_CLR) {
        return klad_slot_clr_set_attr(handle, attr);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_s32 klad_slot_instance_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_get_attr(handle, attr);
    } else if (klad_type == HI_KLAD_TA) {
        return klad_slot_ta_get_attr(handle, attr);
    } else if (klad_type == HI_KLAD_FP) {
        return klad_slot_fp_get_attr(handle, attr);
    } else if (klad_type == HI_KLAD_NONCE) {
        return klad_slot_nonce_get_attr(handle, attr);
    } else if (klad_type == HI_KLAD_CLR) {
        return klad_slot_clr_get_attr(handle, attr);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_s32 klad_slot_instance_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey_attr)
{
    return klad_slot_com_set_rootkey_attr(handle, rootkey_attr);
}

hi_s32 klad_slot_instance_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey_attr)
{
    return klad_slot_com_get_rootkey_attr(handle, rootkey_attr);
}

hi_s32 klad_slot_instance_attach(hi_handle handle, hi_handle target)
{
    return klad_slot_mgmt_attach_ks(handle, target);
}

hi_s32 klad_slot_instance_detach(hi_handle handle, hi_handle target)
{
    return klad_slot_mgmt_detach_ks(handle, target);
}

hi_s32 klad_slot_instance_set_session_key(hi_handle handle, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    if (session_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_set_session_key(handle, session_key);
    } else if (klad_type == HI_KLAD_FP) {
        return klad_slot_fp_set_session_key(handle, session_key);
    } else if (klad_type == HI_KLAD_NONCE) {
        return klad_slot_nonce_set_session_key(handle, session_key);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_s32 klad_slot_instance_set_content_key(hi_handle handle, const hi_klad_content_key *content_key)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    if (content_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_set_content_key(handle, content_key);
    } else if (klad_type == HI_KLAD_CLR) {
        hi_klad_clear_key clear_key = {0};
        clear_key.key_size = content_key->key_size;
        clear_key.odd = content_key->odd;
        if (memcpy_s(clear_key.key, sizeof(clear_key.key), content_key->key, HI_KLAD_MAX_KEY_LEN) != EOK) {
            return HI_ERR_KLAD_SEC_FAILED;
        }
        return klad_slot_clr_set_key(handle, &clear_key);
    } else {
        print_err_code(HI_ERR_KLAD_INVALID_PARAM);
        return HI_ERR_KLAD_INVALID_PARAM;
    }
}

hi_s32 klad_slot_instance_start(hi_handle handle)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_start(handle);
    } else if (klad_type == HI_KLAD_TA) {
        return klad_slot_ta_start(handle);
    } else if (klad_type == HI_KLAD_FP) {
        return klad_slot_fp_start(handle);
    } else if (klad_type == HI_KLAD_NONCE) {
        return klad_slot_nonce_start(handle);
    } else if (klad_type == HI_KLAD_CLR) {
        return klad_slot_clr_start(handle);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_s32 klad_slot_instance_async_start(hi_handle handle, const klad_callback *call_back)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    if (call_back == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_async_start(handle, call_back);
    }
    print_err_code(HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

hi_s32 klad_slot_instance_stop(hi_handle handle)
{
    hi_s32 ret;
    hi_u32 klad_type = 0;

    if (klad_slot_instance_initialzed(handle) == HI_FALSE) {
        return HI_SUCCESS;
    }
    ret = __klad_slot_type(handle, &klad_type);
    if (ret != HI_SUCCESS) {
        print_err_hex3(handle, klad_type, ret);
        return ret;
    }

    if (klad_type == HI_KLAD_COM) {
        return klad_slot_com_stop(handle);
    } else if (klad_type == HI_KLAD_TA) {
        return klad_slot_ta_stop(handle);
    } else if (klad_type == HI_KLAD_FP) {
        return klad_slot_fp_stop(handle);
    } else if (klad_type == HI_KLAD_NONCE) {
        return klad_slot_nonce_stop(handle);
    } else if (klad_type == HI_KLAD_CLR) {
        return klad_slot_clr_stop(handle);
    }

    print_err_hex3(handle, klad_type, HI_ERR_KLAD_INVALID_PARAM);
    return HI_ERR_KLAD_INVALID_PARAM;
}

/*
 *  ==================keyaldder soft instance defination.=========================
 * 1: define the methods of all kinds of Keyladder.
 * 2: define the create method and destroy method.
 * 3: In order to reduce memory fragmentation, all the alloced memory block add to the used list(mgmt->xxx_list)
 *    and remove to the free list(mgmt->xxx_empty_list) if destroy the instance.
 */
static hi_s32 __klad_slot_check_rk_attr(const hi_rootkey_attr *attr)
{
    if ((attr->rootkey_sel >=  HI_ROOTKEY_SLOT_MAX) ||
        (attr->level >=  HI_ROOTKEY_LEVEL_MAX)) {
        print_err_hex2(attr->rootkey_sel, attr->level);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return HI_SUCCESS;
}

static hi_s32 __klad_slot_check_attr(const hi_klad_attr *attr)
{
    if (attr->key_cfg.engine >=  HI_CRYPTO_ENGINE_ALG_MAX) {
        print_err_hex(attr->key_cfg.engine);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return HI_SUCCESS;
}

static hi_s32 __klad_slot_check_session_key(const hi_klad_session_key *session_key)
{
    if ((session_key->level > HI_KLAD_LEVEL_MAX) ||
        (session_key->alg > HI_KLAD_ALG_TYPE_MAX) ||
        (session_key->key_size != HI_KLAD_MAX_SESSION_KEY_LEN)) {
        print_err_hex3(session_key->level, session_key->alg, session_key->key_size);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return HI_SUCCESS;
}

static hi_s32 __klad_slot_check_content_key(const hi_klad_content_key *content_key)
{
    if ((content_key->alg > HI_KLAD_ALG_TYPE_MAX) ||
        (content_key->key_size > HI_KLAD_MAX_KEY_LEN)) {
        print_err_hex2(content_key->alg, content_key->key_size);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return HI_SUCCESS;
}

static hi_s32 klad_slot_com_set_rk_attr_impl(struct com_klad_slot *instance, const hi_rootkey_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    ret = __klad_slot_check_rk_attr(attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_check_rk_attr, ret);
        return ret;
    }

    mutex_lock(&instance->lock);

    if (atomic_read(&instance->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }

    errno = memcpy_s(&instance->rk_attr, sizeof(instance->rk_attr), attr, sizeof(hi_rootkey_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->rk_attr_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_com_get_rk_attr_impl(struct com_klad_slot *instance, hi_rootkey_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(attr, sizeof(hi_rootkey_attr), &instance->rk_attr, sizeof(instance->rk_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    ret = HI_SUCCESS;
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_com_set_attr_impl(struct com_klad_slot *instance, const hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    ret = __klad_slot_check_attr(attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_check_attr, ret);
        return ret;
    }
    mutex_lock(&instance->lock);

    if (atomic_read(&instance->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }

    instance->base.klad_type = get_klad_type(attr->klad_cfg.klad_type);
    errno = memcpy_s(&instance->attr, sizeof(hi_klad_attr), attr, sizeof(*attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->attr_cnt);

    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_com_get_attr_impl(struct com_klad_slot *instance, hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    errno = memcpy_s(attr, sizeof(hi_klad_attr), &instance->attr, sizeof(instance->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_com_set_session_key_impl(struct com_klad_slot *instance, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    errno_t errno;
    hi_klad_level level = session_key->level;

    ret = __klad_slot_check_session_key(session_key);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_check_session_key, ret);
        return ret;
    }

    mutex_lock(&instance->lock);

    if (atomic_read(&instance->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }

    errno = memcpy_s(&instance->session_key[level], sizeof(instance->session_key[level]),
                     session_key, sizeof(hi_klad_session_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->session_cnt[level]);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_com_set_content_key_impl(struct com_klad_slot *instance, const hi_klad_content_key *content_key)
{
    hi_s32 ret;
    errno_t errno;

    ret = __klad_slot_check_content_key(content_key);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_check_content_key, ret);
        return ret;
    }

    mutex_lock(&instance->lock);

    if (atomic_read(&instance->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }

    errno = memcpy_s(&instance->content_key, sizeof(instance->content_key),
                     content_key, sizeof(hi_klad_content_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->content_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

hi_s32 klad_slot_com_create_impl(struct com_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_create_attr hkl_attr = {0};

    if (slot == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    /* Any instance only create HW keyladder once. */
    if ((slot->base.hw_handle != 0) && (slot->base.hw_handle != HI_INVALID_HANDLE)) {
        return HI_ERR_KLAD_HAVE_CREATED;
    }

    ret = ctl_klad_com_attr_prepare(slot, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_attr_prepare, ret);
        goto out;
    }

    ret = ctl_klad_com_create(&slot->base.hw_handle, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_create, ret);
        goto out;
    }
out:
    return ret;
}

hi_s32 klad_slot_com_start_impl(struct com_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_com_entry entry = {0};

    if (slot == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    ret = ctl_klad_com_prepare(slot, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_prepare, ret);
        goto out;
    }
    /* IF HW keyladder is not created, return error, can not start keyladder. */
    if ((slot->base.hw_handle == 0) || (slot->base.hw_handle == HI_INVALID_HANDLE)) {
        print_err_hex2(slot->base.hw_handle, HI_ERR_KLAD_NOT_CREATED);
        return HI_ERR_KLAD_NOT_CREATED;
    }

    ret = ctl_klad_com_startup(slot, &entry);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_startup, ret);
        goto out;
    }
out:
    return ret;
}

static hi_s32 klad_slot_com_start_synchronous_impl(struct com_klad_slot *slot)
{
    hi_s32 ret;

    mutex_lock(&slot->lock);

    /* If HW keyladder has created, start keyladder directly. */
    ret = klad_slot_com_create_impl(slot);
    if (ret != HI_SUCCESS && ret != HI_ERR_KLAD_HAVE_CREATED) {
        print_err_func(klad_slot_com_create_impl, ret);
        goto out;
    }

    ret = klad_slot_com_start_impl(slot);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_com_start_impl, ret);
        goto out;
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_com_start_asynchronous_impl(struct com_klad_slot *slot, const klad_callback *call_back)
{
    hi_s32 ret;

    ctl_klad_msgq();

    mutex_lock(&slot->lock);

    if (atomic_read(&slot->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }

    ret = ctl_klad_com_asynchronize_startup(slot, call_back);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_asynchronize_startup, ret);
    }

out:
    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_com_stop_impl(struct com_klad_slot *slot)
{
    hi_s32 ret = HI_SUCCESS;

    mutex_lock(&slot->lock);

    if (atomic_read(&slot->base.ref_async) != 0) {
        ret = HI_ERR_KLAD_ASYNC_UNFINISHED;
        goto out;
    }
    if (slot->base.hw_handle != 0 && slot->base.hw_handle != HI_INVALID_HANDLE) {
        ret = ctl_klad_com_destroy(slot->base.hw_handle);
        if (ret != HI_SUCCESS) {
            print_err_func(ctl_klad_com_destroy, ret);
            goto out;
        }
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

/*
 * com keyaldder soft instance defination.
 */
static struct klad_com_ops g_sw_com_klad_slot_ops = {
    .set_rootkey_attr          = klad_slot_com_set_rk_attr_impl,
    .get_rootkey_attr          = klad_slot_com_get_rk_attr_impl,
    .set_attr                  = klad_slot_com_set_attr_impl,
    .get_attr                  = klad_slot_com_get_attr_impl,
    .set_session_key           = klad_slot_com_set_session_key_impl,
    .set_content_key           = klad_slot_com_set_content_key_impl,
    .start                     = klad_slot_com_start_synchronous_impl,
    .start_asynchronous        = klad_slot_com_start_asynchronous_impl,
    .stop                      = klad_slot_com_stop_impl,
};

struct klad_com_ops *get_sw_com_klad_slot_ops(hi_void)
{
    return &g_sw_com_klad_slot_ops;
}

static hi_s32 klad_slot_fp_set_attr_impl(struct fp_klad_slot *instance, const hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    instance->base.klad_type = get_klad_type(attr->klad_cfg.klad_type);
    errno = memcpy_s(&instance->attr, sizeof(instance->attr), attr, sizeof(hi_klad_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->attr_cnt);

    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_fp_get_attr_impl(struct fp_klad_slot *instance, hi_klad_attr *attr)
{
    errno_t errno;

    mutex_lock(&instance->lock);

    errno = memcpy_s(attr, sizeof(hi_klad_attr), &instance->attr, sizeof(instance->attr));
    if (errno != EOK) {
        mutex_unlock(&instance->lock);
        return HI_ERR_KLAD_SEC_FAILED;
    }

    mutex_unlock(&instance->lock);

    return HI_SUCCESS;
}

static hi_s32 klad_slot_fp_set_session_key_impl(struct fp_klad_slot *instance, const hi_klad_session_key *session_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;
    hi_klad_level level = session_key->level;

    if (level >= HI_KLAD_LEVEL_MAX) {
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->session_key[level], sizeof(instance->session_key[level]),
                     session_key, sizeof(hi_klad_session_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->session_cnt[level]);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_fp_set_fp_key_impl(struct fp_klad_slot *instance, const hi_klad_fp_key *fp_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->fp_key, sizeof(instance->fp_key), fp_key, sizeof(hi_klad_fp_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->fp_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 __klad_slot_fp_create_impl(struct fp_klad_slot *slot)
{
    hi_s32 ret;
    hi_klad_create_attr hkl_attr = {0};

    /* Any instance only create HW keyladder once. */
    if ((slot->base.hw_handle != 0) && (slot->base.hw_handle != HI_INVALID_HANDLE)) {
        return HI_ERR_KLAD_HAVE_CREATED;
    }

    ret = ctl_klad_fp_attr_prepare(slot, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_attr_prepare, ret);
        goto out;
    }

    ret = ctl_klad_fp_create(&slot->base.hw_handle, &hkl_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_com_create, ret);
    }
out:
    return ret;
}

static hi_s32 __klad_slot_fp_start_impl(struct fp_klad_slot *slot)
{
    hi_s32 ret;

    /* IF HW keyladder is not created, return error, can not start keyladder. */
    if ((slot->base.hw_handle == 0) || (slot->base.hw_handle == HI_INVALID_HANDLE)) {
        print_err_hex2(slot->base.hw_handle, HI_ERR_KLAD_NOT_CREATED);
        return HI_ERR_KLAD_NOT_CREATED;
    }

    ret = ctl_klad_fp_startup(slot);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_startup, ret);
        goto out;
    }
out:
    return ret;
}

static hi_s32 __klad_slot_fp_crypto_impl(struct fp_klad_slot *slot)
{
    hi_s32 ret;

    /* IF HW keyladder is not created, return error, can not start keyladder. */
    if ((slot->base.hw_handle == 0) || (slot->base.hw_handle == HI_INVALID_HANDLE)) {
        print_err_hex2(slot->base.hw_handle, HI_ERR_KLAD_NOT_CREATED);
        return HI_ERR_KLAD_NOT_CREATED;
    }

    ret = ctl_klad_fp_crypto(slot);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_crypto, ret);
        goto out;
    }
out:
    return ret;
}

static hi_s32 __klad_slot_fp_route_impl(struct fp_klad_slot *instance)
{
    hi_s32 ret;

    ret = ctl_klad_fp_route(instance);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_fp_route, ret);
    }

    return ret;
}

static hi_s32 klad_slot_fp_start_impl(struct fp_klad_slot *instance)
{
    hi_s32 ret;
    mutex_lock(&instance->lock);

    /* If HW keyladder has created, start keyladder directly. */
    ret = __klad_slot_fp_create_impl(instance);
    if (ret != HI_SUCCESS && ret != HI_ERR_KLAD_HAVE_CREATED) {
        print_err_func(__klad_slot_fp_create_impl, ret);
        goto out;
    }

    ret = __klad_slot_fp_start_impl(instance);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_fp_start_impl, ret);
        goto out;
    }
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_fp_crypto_impl(struct fp_klad_slot *instance)
{
    hi_s32 ret;
    mutex_lock(&instance->lock);

    /* If HW keyladder has created, start keyladder directly. */
    ret = __klad_slot_fp_create_impl(instance);
    if (ret != HI_SUCCESS && ret != HI_ERR_KLAD_HAVE_CREATED) {
        print_err_func(__klad_slot_fp_create_impl, ret);
        goto out;
    }

    ret = __klad_slot_fp_crypto_impl(instance);
    if (ret != HI_SUCCESS) {
        print_err_func(__klad_slot_fp_crypto_impl, ret);
        goto out;
    }
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_fp_route_impl(struct fp_klad_slot *instance)
{
    hi_s32 ret;
    mutex_lock(&instance->lock);

    ret = __klad_slot_fp_route_impl(instance);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_fp_route_impl, ret);
        goto out;
    }
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_fp_stop_impl(struct fp_klad_slot *slot)
{
    hi_s32 ret = HI_SUCCESS;

    mutex_lock(&slot->lock);

    if (slot->base.hw_handle != 0 && slot->base.hw_handle != HI_INVALID_HANDLE) {
        ret = ctl_klad_fp_destroy(slot->base.hw_handle);
        if (ret != HI_SUCCESS) {
            print_err_func(ctl_klad_fp_destroy, ret);
            goto out;
        }
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

/*
 * flash protection keyaldder soft instance defination.
 */
static struct klad_fp_ops g_sw_fp_klad_slot_ops = {
    .set_attr                  = klad_slot_fp_set_attr_impl,
    .get_attr                  = klad_slot_fp_get_attr_impl,
    .set_session_key           = klad_slot_fp_set_session_key_impl,
    .set_fp_key                = klad_slot_fp_set_fp_key_impl,
    .route                     = klad_slot_fp_route_impl,
    .start                     = klad_slot_fp_start_impl,
    .crypto                    = klad_slot_fp_crypto_impl,
    .stop                      = klad_slot_fp_stop_impl,
};

struct klad_fp_ops *get_sw_fp_klad_slot_ops(hi_void)
{
    return &g_sw_fp_klad_slot_ops;
}

hi_s32 klad_slot_ta_set_attr_impl(struct ta_klad_slot *instance, const hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    if (instance == HI_NULL || attr == HI_NULL) {
        return HI_ERR_KLAD_NULL_PTR;
    }

    mutex_lock(&instance->lock);

    instance->base.klad_type = get_klad_type(attr->klad_cfg.klad_type);
    errno = memcpy_s(&instance->attr, sizeof(instance->attr), attr, sizeof(hi_klad_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->attr_cnt);

    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_ta_get_attr_impl(struct ta_klad_slot *instance, hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    errno = memcpy_s(attr, sizeof(hi_klad_attr), &instance->attr, sizeof(instance->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_ta_set_session_key_impl(struct ta_klad_slot *instance, const hi_klad_ta_key *ta_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->session_ta_key, sizeof(instance->session_ta_key), ta_key, sizeof(hi_klad_ta_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->session_ta_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_ta_set_trans_data_impl(struct ta_klad_slot *instance, const hi_klad_trans_data *trans_data)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->trans_data, sizeof(instance->trans_data),
                     trans_data, sizeof(hi_klad_trans_data));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->trans_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_ta_set_content_key_impl(struct ta_klad_slot *instance, const hi_klad_ta_key *ta_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->content_ta_key, sizeof(instance->content_ta_key), ta_key, sizeof(hi_klad_ta_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->content_ta_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_ta_start_impl(struct ta_klad_slot *instance)
{
    hi_s32 ret = HI_FAILURE;
    mutex_lock(&instance->lock);

    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_ta_stop_impl(struct ta_klad_slot *slot)
{
    hi_s32 ret = HI_SUCCESS;

    mutex_lock(&slot->lock);

    if (slot->base.hw_handle != 0 && slot->base.hw_handle != HI_INVALID_HANDLE) {
        ret = ctl_klad_ta_destroy(slot->base.hw_handle);
        if (ret != HI_SUCCESS) {
            print_err_func(ctl_klad_ta_destroy, ret);
            goto out;
        }
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

/*
 * ta keyaldder soft instance defination.
 */
static struct klad_ta_ops g_sw_ta_klad_slot_ops = {
    .set_attr                  = klad_slot_ta_set_attr_impl,
    .get_attr                  = klad_slot_ta_get_attr_impl,
    .set_session_ta_key        = klad_slot_ta_set_session_key_impl,
    .set_trans_data            = klad_slot_ta_set_trans_data_impl,
    .set_content_ta_key        = klad_slot_ta_set_content_key_impl,
    .start                     = klad_slot_ta_start_impl,
    .stop                      = klad_slot_ta_stop_impl,
};

struct klad_ta_ops *get_sw_ta_klad_slot_ops(hi_void)
{
    return &g_sw_ta_klad_slot_ops;
}

static hi_s32 klad_slot_nonce_set_attr_impl(struct nonce_klad_slot *instance, const hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    instance->base.klad_type = get_klad_type(attr->klad_cfg.klad_type);

    errno = memcpy_s(&instance->attr, sizeof(instance->attr), attr, sizeof(hi_klad_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->attr_cnt);

    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_nonce_get_attr_impl(struct nonce_klad_slot *instance, hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    errno = memcpy_s(attr, sizeof(hi_klad_attr), &instance->attr, sizeof(instance->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_nonce_set_session_key_impl(struct nonce_klad_slot *instance,
                                                   const hi_klad_session_key *session_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;
    hi_klad_level level = session_key->level;

    if (level >= HI_KLAD_LEVEL_MAX) {
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->session_key[level], sizeof(instance->session_key[level]),
                     session_key, sizeof(hi_klad_session_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->session_cnt[level]);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_nonce_set_key_impl(struct nonce_klad_slot *instance, const hi_klad_nonce_key *nonce_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->nonce_key, sizeof(instance->nonce_key), nonce_key, sizeof(hi_klad_nonce_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->nonce_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_nonce_start_impl(struct nonce_klad_slot *instance)
{
    hi_s32 ret = HI_FAILURE;
    mutex_lock(&instance->lock);

    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_nonce_stop_impl(struct nonce_klad_slot *slot)
{
    hi_s32 ret = HI_SUCCESS;

    mutex_lock(&slot->lock);

    if (slot->base.hw_handle != 0 && slot->base.hw_handle != HI_INVALID_HANDLE) {
        ret = ctl_klad_nonce_destroy(slot->base.hw_handle);
        if (ret != HI_SUCCESS) {
            print_err_func(ctl_klad_nonce_destroy, ret);
            goto out;
        }
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

/*
 * nonce keyaldder soft instance defination.
 */
static struct klad_nonce_ops g_sw_nonce_klad_slot_ops = {
    .set_attr                  = klad_slot_nonce_set_attr_impl,
    .get_attr                  = klad_slot_nonce_get_attr_impl,
    .set_session_key           = klad_slot_nonce_set_session_key_impl,
    .set_nonce_key             = klad_slot_nonce_set_key_impl,
    .start                     = klad_slot_nonce_start_impl,
    .stop                      = klad_slot_nonce_stop_impl,
};

struct klad_nonce_ops *get_sw_nonce_klad_slot_ops(hi_void)
{
    return &g_sw_nonce_klad_slot_ops;
}

static hi_s32 klad_slot_clr_route_set_attr_impl(struct clr_route_slot *instance, const hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    instance->base.klad_type = get_klad_type(attr->klad_cfg.klad_type);

    errno = memcpy_s(&instance->attr, sizeof(instance->attr), attr, sizeof(hi_klad_attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->attr_cnt);

    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_clr_route_get_attr_impl(struct clr_route_slot *instance, hi_klad_attr *attr)
{
    hi_s32 ret;
    errno_t errno;

    mutex_lock(&instance->lock);

    errno = memcpy_s(attr, sizeof(hi_klad_attr), &instance->attr, sizeof(instance->attr));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    ret = HI_SUCCESS;

out:
    mutex_unlock(&instance->lock);

    return ret;
}

static hi_s32 klad_slot_clr_route_set_clr_key_impl(struct clr_route_slot *instance, const hi_klad_clear_key *clr_key)
{
    hi_s32 ret = HI_SUCCESS;
    errno_t errno;

    mutex_lock(&instance->lock);
    errno = memcpy_s(&instance->clr_key, sizeof(instance->clr_key), clr_key, sizeof(hi_klad_clear_key));
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        goto out;
    }
    atomic64_inc(&instance->clr_cnt);
out:
    mutex_unlock(&instance->lock);
    return ret;
}

static hi_s32 klad_slot_clr_route_start_impl(struct clr_route_slot *slot)
{
    hi_s32 ret;

    mutex_lock(&slot->lock);

    ret = ctl_klad_clr_process(slot);
    if (ret != HI_SUCCESS) {
        print_err_func(ctl_klad_clr_process, ret);
        goto out;
    }
out:
    mutex_unlock(&slot->lock);
    return ret;
}

static hi_s32 klad_slot_clr_route_stop_impl(struct clr_route_slot *slot)
{
    /* nothing to be done. Not any hardware resource. */
    return HI_SUCCESS;
}

/*
 * clear route keyaldder soft instance defination.
 */
static struct klad_clr_route_ops g_sw_clr_route_slot_ops = {
    .set_attr                  = klad_slot_clr_route_set_attr_impl,
    .get_attr                  = klad_slot_clr_route_get_attr_impl,
    .set_clr_key               = klad_slot_clr_route_set_clr_key_impl,
    .start                     = klad_slot_clr_route_start_impl,
    .stop                      = klad_slot_clr_route_stop_impl,
};

struct klad_clr_route_ops *get_sw_clr_route_slot_ops(hi_void)
{
    return &g_sw_clr_route_slot_ops;
}
