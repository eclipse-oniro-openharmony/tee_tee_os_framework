/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */
#include "icc_core.h"

extern void irq_lock();
extern void irq_unlock();

struct icc_control g_icc_ctrl = { 0 };
static u32 g_icctask_running_flag = 0;
static u32 fifo_put_with_header(struct icc_channel_fifo *fifo, u8 *head_buf, u32 head_len, u8 *data_buf, u32 data_len)
{
    u32 tail_idle_size;
    u32 write = fifo->write;
    u32 read = fifo->read;
    char *base_addr = (char *)((char *)fifo + sizeof(struct icc_channel_fifo));
    u32 buf_len = fifo->size;
    errno_t err;

    /* 空闲缓冲区大小 */
    if (read > write) {
        tail_idle_size = (read - write);
    } else {
        tail_idle_size = (buf_len - write);
    }

    /* 先填充头部 */
    if (tail_idle_size < head_len) {
        err = memcpy_s((void *)(write + base_addr), tail_idle_size, (void *)head_buf, tail_idle_size);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        err = memcpy_s((void *)base_addr, read, (void *)(head_buf + tail_idle_size), (head_len - tail_idle_size));
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        write = head_len - tail_idle_size;
        tail_idle_size = 0;
    } else {
        err = memcpy_s((void *)(write + base_addr), tail_idle_size, (void *)head_buf, head_len);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        tail_idle_size = tail_idle_size - head_len;
        write = (tail_idle_size == 0) ? 0 : (write + head_len);
    }

    /* 再填充负载 */
    if (tail_idle_size == 0) {
        err = memcpy_s((void *)(write + base_addr), (read - write), (void *)data_buf, data_len);
        if (err != EOK) {
            icc_print_error("<fifo_put_with_header>%d memcpy_s failed, err = %d\n", __LINE__, err);
            return (u32)ICC_ERR;
        }
        write += data_len;
    } else if (tail_idle_size >= data_len) {
        err = memcpy_s((void *)(write + base_addr), tail_idle_size, (void *)data_buf, data_len);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        write += data_len;
    } else {
        err = memcpy_s((void *)(write + base_addr), tail_idle_size, (void *)data_buf, tail_idle_size);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        err = memcpy_s((void *)base_addr, read, (void *)(data_buf + tail_idle_size), data_len - tail_idle_size);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        write = data_len - tail_idle_size;
    }

    /* 确保最后写完不停在缓冲区结束位置 */
    write = (write == buf_len) ? 0 : write;

    /* 更新写指针 */
    mb();
    fifo->write = write;

    return data_len + head_len;
}

static u32 fifo_get(struct icc_channel_fifo *fifo, u8 *data_buf, u32 data_len, u32 *read)
{
    u32 total_idle_size;
    u32 tail_idle_size; /*lint !e14 */
    u32 write = fifo->write;
    char *base_addr = (char *)fifo + sizeof(struct icc_channel_fifo);
    u32 buf_len = fifo->size;
    u32 readed_len;
    errno_t err;

    if (write >= buf_len) {
        return (u32)ICC_ERR;
    }
    /* 空闲缓冲区大小 */
    if (*read > write) {
        total_idle_size = (buf_len + write - *read);
        tail_idle_size = (buf_len - *read);
    } else {
        total_idle_size = (write - *read);
        tail_idle_size = total_idle_size;
    }

    readed_len = (ICC_MIN(data_len, total_idle_size));
    if (readed_len <= tail_idle_size) {
        err = memcpy_s((void *)data_buf, data_len, (void *)(*read + base_addr), readed_len);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        *read += readed_len;
    } else {
        err = memcpy_s((void *)data_buf, data_len, (void *)(*read + base_addr), tail_idle_size);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        err = memcpy_s((void *)(data_buf + tail_idle_size), (data_len - tail_idle_size), (void *)base_addr,
            readed_len - tail_idle_size);
        if (err != EOK) {
            return (u32)ICC_ERR;
        }
        *read = readed_len - tail_idle_size;
    }

    /* 确保最后读完不停在缓冲区结束位置 */
    *read = (*read >= buf_len) ? (*read - buf_len) : (*read);

    return readed_len;
}


/* 数据包完整性需要保证 */
static u32 fifo_get_with_header(struct icc_channel_fifo *fifo, u8 *data_buf, u32 data_buf_len)
{
    u32 read_len;
    u32 read = fifo->read;
    struct icc_channel_packet packet = { 0 };

    read_len = fifo_get(fifo, (u8 *)&packet, sizeof(packet), &read);
    if (read_len != sizeof(packet)) { /* 读包头错误 */
        icc_print_error("get packet err, read_len:0x%x, packet_size: 0x%x \n", read_len, sizeof(packet));
        (void)icc_channel_packet_dump(&packet);
        return (u32)ICC_ERR;
    }
    if (data_buf_len < packet.len) { /* 传入len比实际包的长度小 */
        icc_print_error("invalid data_len:0x%x, packet.len: 0x%x \n", data_buf_len, packet.len);
        return (u32)ICC_ERR;
    }

    read_len = fifo_get(fifo, data_buf, packet.len, &read);
    if (read_len != packet.len) { /* 读数据错误 */
        icc_print_error("get data err, read_len:0x%x, packet.len: 0x%x \n", read_len, packet.len);
        return (u32)ICC_ERR;
    }

    /* 更新读指针 */
    rmb();
    fifo->read = read;

    return read_len;
}


/* fifo中还有多少空闲空间 */
static u32 fifo_write_space_get(struct icc_channel_fifo *fifo)
{
    u32 write = fifo->write;
    u32 read = fifo->read;
    u32 buf_len = fifo->size;

    /* 空闲缓冲区大小 */
    if (read > write) {
        return (read - write);
    } else {
        return ((buf_len - write) + read);
    }
}


/* fifo中还有多少数据未读取 */
static u32 fifo_read_space_get(struct icc_channel_fifo *fifo)
{
    u32 write = fifo->write;
    u32 read = fifo->read;
    u32 buf_len = fifo->size;

    if (read > write) {
        return (buf_len + write - read);
    } else {
        return (write - read);
    }
}


static u32 fifo_skip(struct icc_channel_fifo *fifo, u32 len)
{
    u32 space = fifo_read_space_get(fifo);
    u32 data_len = ICC_MIN(len, space);
    u32 read = fifo->read;
    read += data_len;
    read = (read >= fifo->size) ? (read - fifo->size) : (read);
    fifo->read = read;

    return data_len;
}

/*lint -save -e732 */
static s32 data_send(u32 cpuid, u32 channel_id, u8 *data, u32 data_len)
{
    s32 ret = ICC_OK;
    u32 len;
    struct icc_channel *channel = g_icc_ctrl.channels[GET_CHN_ID(channel_id)];
    struct icc_channel_packet packet = { 0 };

    packet.channel_id = channel_id;
    packet.src_cpu_id = ICC_THIS_CPU;
    packet.seq_num = 0;
    packet.is_responsed = 0;
    packet.need_responsed = 0;
    packet.len = data_len;
    packet.data = 0;

    irq_lock();

    icc_debug_before_send(&packet); /* 记录debug信息，将发送任务ID及时间戳放入包头中 */

    if ((data_len + sizeof(struct icc_channel_packet)) >= fifo_write_space_get(channel->fifo_send)) { /*lint !e574 */
        ret = ICC_INVALID_NO_FIFO_SPACE;
        goto err_send;
    }

    /* 将包头及负载放入fifo */
    len = fifo_put_with_header(channel->fifo_send, (u8 *)&packet, sizeof(struct icc_channel_packet), data, data_len);
    if (len != (u32)ICC_ERR) {
        len -= sizeof(struct icc_channel_packet);
    } else {
        ret = ICC_SEND_ERR;
        goto err_send;
    }
    if (data_len != len) {
        ret = ICC_SEND_ERR;
        goto err_send; /*lint !e801 */
    }

    ret = bsp_ipc_int_send((IPC_INT_CORE_E)cpuid, (IPC_INT_LEV_E)channel->ipc_send_irq_id);
    if (ret != 0) {
        icc_print_error("ipc send fail,ret:0x%x \n", ret);
        goto err_send; /*lint !e801 */
    }

    icc_debug_after_send(channel, &packet, data);

    irq_unlock();

    return (s32)len;

err_send:
    irq_unlock();
    return ret;
}

void handle_channel_recv_data(struct icc_channel *channel)
{
    struct icc_channel_packet packet = { 0 };
    struct icc_channel_vector *vector;
    u32 read_len;
    u32 read;

    irq_lock();
    read = channel->fifo_recv->read;
    read_len = fifo_get(channel->fifo_recv, (u8 *)&packet, sizeof(packet), &read);
    if (read_len != sizeof(packet)) {
        irq_unlock();
        icc_print_notice("notice: %s[%d], read=0x%x, write=0x%x, read_len=%d, packet_size=%d\n", channel->name,
            (int)channel->id, channel->fifo_recv->read, channel->fifo_recv->write, (int)read_len, sizeof(packet));

        (void)icc_channel_packet_dump(&packet);
        return;
    }

    if (GET_CHN_ID(packet.channel_id) >= ICC_CHN_ID_MAX) {
        icc_packet_print(&packet);
        irq_unlock();
        icc_print_error("invalid packet, unrecovery\n");
        return;
    }

    if (GET_FUNC_ID(packet.channel_id) >= channel->func_size) {
        /* 无效包跳过 */
        (void)fifo_skip(channel->fifo_recv, packet.len + read_len);
        irq_unlock();
        icc_print_error("skip packet!channel_id:0x%x,task_id:0x%x\n", packet.channel_id, packet.task_id);
        return;
    }

    vector = &channel->vector[GET_FUNC_ID(packet.channel_id)];

    if (!packet.len) { /* 空包，跳过packet */
        channel->fifo_recv->read = read;
    }

    irq_unlock();

    if (vector->read_cb) {
        icc_print_debug("cb func:%p id:0x%x\n", vector->read_cb, packet.channel_id);
        icc_debug_before_recv(&packet);
        (void)vector->read_cb(packet.channel_id, packet.len, vector->read_context);
        icc_debug_after_recv(&packet);
    }

    return;
}

void handle_channel_recv(struct icc_channel *channel)
{
    u32 read = 0;

    /* 防止快速掉电内存中内容不丢失，造成的对fifo的判断错误 */
    if (channel->fifo_recv->magic == ICC_CHN_MAGIC_SIGN) {
        channel->fifo_recv->magic = ICC_CHN_MAGIC_UNSIGN;
        channel->ready_recv = 1;
    }
    if (channel->ready_recv) {
        /* 把fifo中消息全部读走(需要等对方初始化后才能使用) */
        while (fifo_read_space_get(channel->fifo_recv) >= sizeof(struct icc_channel_packet)) {
            read = channel->fifo_recv->read;
            handle_channel_recv_data(channel);
            if (channel->fifo_recv->read == read) {
                break;
            }
        }

        /* 写回调默认使用子通道0 */
        if (fifo_write_space_get(channel->fifo_recv) == channel->fifo_recv->size && channel->vector->write_cb) {
            (void)channel->vector->write_cb(channel->id, NULL);
        }
    }
}

static u32 icctask_should_stop(void)
{
    if (g_icctask_running_flag != 0) {
        g_icctask_running_flag = 0;
    }
    return g_icctask_running_flag;
}

int icc_task_private_func(void *obj)
{
    struct icc_channel *channel = obj;

    while (!icctask_should_stop()) {
        handle_channel_recv(channel);
        osl_sem_down(&channel->private_task_sem);
    }
    return ICC_OK;
}

int icc_task_shared_func(void *obj)

{
    struct icc_channel *channel = NULL;
    u32 i;
    UNUSED(obj);
    while (!icctask_should_stop()) {
        for (i = 0; i < ICC_CHN_ID_MAX; i++) {
            channel = g_icc_ctrl.channels[i];
            if (!channel) {
                continue;
            }

            if (channel->mode.union_stru.task_shared) {
                handle_channel_recv(channel);
            }
        }
        icc_wake_unlock(&g_icc_ctrl.wake_lock);
        osl_sem_down(&g_icc_ctrl.shared_task_sem);
    }
    /* pc-lint & build warning cannot clean at the same time */
    return ICC_OK;
} /*lint !e715 */

void icc_notask_sharedipc_func(void)
{
    struct icc_channel *channel = NULL;
    u32 i;

    for (i = ICC_CHN_ACORE_CCORE_MIN; i < ICC_CHN_ID_MAX; i++) {
        channel = g_icc_ctrl.channels[i];
        if (!channel) {
            continue;
        }

        if ((!channel->mode.union_stru.task_shared) && (!channel->mode.union_stru.no_task)) {
            osl_sem_up(&(channel->private_task_sem)); /*lint !e661 */
        } else if (channel->mode.union_stru.no_task) {
            handle_channel_recv(channel);
        }
    }
}

void icc_ipc_isr(u32 data)
{
    struct icc_channel *channel = NULL;
    u32 channel_id = data;

    icc_debug_in_isr();

    if (channel_id == ICC_NOTASK_SHAREDIPC_IDX) {
        icc_notask_sharedipc_func();
    } else if (channel_id == ICC_SHAREDTASK_SHAREDIPC_IDX) {
        /* coverity[dead_error_begin] */
        icc_wake_lock(&g_icc_ctrl.wake_lock);
        osl_sem_up(&g_icc_ctrl.shared_task_sem);
    } else {
        if (channel_id < ICC_CHN_ID_MAX)
            channel = g_icc_ctrl.channels[channel_id];
        else {
            icc_print_error("err,chan_id=0x%x\n", channel_id);
            return;
        }

        if ((!channel->mode.union_stru.task_shared) && (!channel->mode.union_stru.no_task)) {
            osl_sem_up(&(channel->private_task_sem)); /*lint !e661 */
        } else if (channel->mode.union_stru.no_task) {
            handle_channel_recv(channel);
        }
    }
}

/* 根据fifo头信息初始化通道 */
/*lint --e{578} */
struct icc_channel *icc_channel_init(struct icc_init_info *info, s32 *ret)
{
    struct icc_channel *channel;
    static int shared_init_flag = 0;
    errno_t err;

    *ret = ICC_OK;

    channel = (struct icc_channel *)osl_malloc(sizeof(struct icc_channel));
    if (!channel) {
        *ret = ICC_MALLOC_CHANNEL_FAIL;
        goto error_channel; /*lint !e801 */
    }
    err = memset_s(channel, sizeof(struct icc_channel), 0, sizeof(struct icc_channel));
    if (err != EOK) {
        goto error_vector;
    }
    channel->id = info->real_channel_id; /* 直接使用real channel id */
    channel->name = info->name;
    channel->mode.val = info->mode;

    /* 发送fifo本侧初始化，接收fifo对侧初始化 */
    channel->fifo_send = (struct icc_channel_fifo *)(info->send_addr); /*lint !e826 */
    channel->fifo_recv = (struct icc_channel_fifo *)(info->recv_addr); /*lint !e826 */
    icc_restore_recv_channel_flag(channel->fifo_recv);

    err = memset_s(channel->fifo_send, sizeof(struct icc_channel_fifo), 0, sizeof(struct icc_channel_fifo));
    if (err != EOK) {
        goto error_vector;
    }
    channel->fifo_send->size = info->fifo_size;
    channel->fifo_send->magic = ICC_CHN_MAGIC_SIGN; /* 通知对方本核的该fifo是否初始化完成 */

    /* 接收向量初始化 */
    channel->func_size = info->func_size;
    channel->vector = (struct icc_channel_vector *)osl_malloc(sizeof(struct icc_channel_vector) * channel->func_size);
    if (!channel->vector) {
        *ret = ICC_MALLOC_VECTOR_FAIL;
        goto error_vector; /*lint !e801 */
    }
    err = memset_s(channel->vector, sizeof(struct icc_channel_vector) * channel->func_size, 0,
        sizeof(struct icc_channel_vector) * channel->func_size);
    if (err != EOK) {
        goto error_task;
    }

    channel->ipc_send_irq_id = info->ipc_send_irq_id;
    channel->ipc_recv_irq_id = info->ipc_recv_irq_id;

    if ((!channel->mode.union_stru.task_shared) && (!channel->mode.union_stru.no_task)) {
        icc_private_sem_init(&channel->private_task_sem);

        /* coverity[overwrite_var] */
        if (ICC_ERR == osl_task_init((char *)channel->name, ICC_TASK_PRIVATE_PRI, ICC_TASK_STK_SIZE,
            (void *)icc_task_private_func, (void *)channel, &channel->private_task_id)) { /*lint !e611 */
            *ret = ICC_CREATE_TASK_FAIL;                                                  /* [false alarm]:fortify */
            goto error_task;                                                              /*lint !e801 */
        }
    }

    channel->state = ICC_CHN_OPENED;
    channel->ready_recv = 0;

    /* 私有IPC中断源 */
    if (!channel->mode.union_stru.ipc_shared) {
        if (ICC_ERR ==
            bsp_ipc_int_connect((IPC_INT_LEV_E)channel->ipc_recv_irq_id, (voidfuncptr)icc_ipc_isr, channel->id)) {
            *ret = ICC_REGISTER_INT_FAIL;
            goto error_task; /*lint !e801 */
        }
        if (ICC_ERR == bsp_ipc_int_enable((IPC_INT_LEV_E)channel->ipc_recv_irq_id)) {
            *ret = ICC_REGISTER_INT_FAIL;
            goto error_task; /*lint !e801 */
        }
    }

    /* 无任务或私有任务共享IPC中断 */
    if ((channel->mode.union_stru.ipc_shared) &&
        ((channel->mode.union_stru.no_task) ||
        ((!channel->mode.union_stru.task_shared) && (!channel->mode.union_stru.no_task))) &&
        (shared_init_flag == 0)) {
        if (ICC_ERR == bsp_ipc_int_connect((IPC_INT_LEV_E)channel->ipc_recv_irq_id, (voidfuncptr)icc_ipc_isr,
            ICC_NOTASK_SHAREDIPC_IDX)) {
            *ret = ICC_REGISTER_INT_FAIL;
            goto error_task; /*lint !e801 */
        }
        if (ICC_ERR == bsp_ipc_int_enable((IPC_INT_LEV_E)channel->ipc_recv_irq_id)) {
            *ret = ICC_REGISTER_INT_FAIL;
            goto error_task; /*lint !e801 */
        }
        shared_init_flag = 1;
    }

    return channel;

error_task:
    icc_safe_free(channel->vector);
error_vector:
    icc_safe_free(channel);
error_channel:
    icc_print_error("chan init errno=0x%x,chan_id=0x%x\n", (unsigned int)(uintptr_t)ret, info->real_channel_id);
    return NULL;
}

s32 bsp_icc_init(void)
{
    s32 ret;
    errno_t err;
    err = memset_s(&g_icc_ctrl, sizeof(struct icc_control), 0, sizeof(struct icc_control));
    if (err != EOK) {
        return ICC_ERR;
    }
    g_icc_ctrl.cpu_id = ICC_THIS_CPU;

    /* 不用通道指针置空，指针数组全部 */
    err = memset_s(g_icc_ctrl.channels, ICC_CHN_ID_MAX * sizeof(struct icc_channel *), 0,
        ICC_CHN_ID_MAX * sizeof(struct icc_channel *));
    if (err != EOK) {
        return ICC_ERR;
    }
    g_icc_ctrl.channel_size = ICC_CHN_ID_MAX;

    ret = icc_channels_init();
    if (ret) {
        icc_print_error("chan fifo init err\n");
        goto icc_channels_init_err; /*lint !e801 */
    }

    icc_wake_lock_init(&g_icc_ctrl.wake_lock, WAKE_LOCK_SUSPEND, "icc_wake");

    ret = icc_debug_init(ICC_CHN_ID_MAX);
    if (ICC_OK != ret) {
        goto icc_channels_init_err; /*lint !e801 */
    }

    (void)icc_pm_init();

    icc_shared_sem_init();

    if (ICC_ERR == icc_shared_task_init()) {
        ret = ICC_CREATE_TASK_FAIL; /* [false alarm]:fortify */
        goto icc_channels_init_err; /*lint !e801 */
    }

    g_icc_ctrl.shared_recv_ipc_irq_id = ICC_RECV_IPC_SHARED;

    if (ICC_ERR == bsp_ipc_int_connect((IPC_INT_LEV_E)g_icc_ctrl.shared_recv_ipc_irq_id, (voidfuncptr)icc_ipc_isr,
        ICC_SHAREDTASK_SHAREDIPC_IDX)) {
        ret = ICC_REGISTER_INT_FAIL;
        goto icc_channels_init_err;
    }
    if (ICC_ERR == bsp_ipc_int_enable((IPC_INT_LEV_E)g_icc_ctrl.shared_recv_ipc_irq_id)) {
        ret = ICC_REGISTER_INT_FAIL;
        goto icc_channels_init_err;
    }

    icc_print_error("ok\n");

    g_icc_ctrl.state = ICC_INITIALIZED;

    return ICC_OK;

icc_channels_init_err:

    icc_print_error("icc init errno: 0x%x\n", ret);

    return ret;
}

s32 bsp_icc_event_register(u32 channel_id, read_cb_func read_cb, void *read_context, write_cb_func write_cb,
    void *write_context)
{
    struct icc_channel_vector *vector = NULL;

    if ((GET_CHN_ID(channel_id) >= ICC_CHN_ID_MAX) || (!g_icc_ctrl.channels[GET_CHN_ID(channel_id)]) ||
        (GET_FUNC_ID(channel_id) >= g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->func_size)) {
        icc_print_error("wrong para chan_id=0x%x\n", channel_id);
        return ICC_INVALID_PARA;
    }
    /*lint --e{409} */
    vector = &(g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->vector[GET_FUNC_ID(channel_id)]);
    if (vector->read_cb != NULL || vector->write_cb != NULL) {
        icc_print_error("%p reged\n", read_cb);
        return ICC_REGISTER_CB_FAIL;
    }

    vector->read_cb = read_cb;
    vector->read_context = read_context;
    vector->write_cb = write_cb;
    vector->write_context = write_context;

    icc_wake_lock(&g_icc_ctrl.wake_lock);
    osl_sem_up(&g_icc_ctrl.shared_task_sem);

    return ICC_OK;
}

s32 bsp_icc_event_unregister(u32 channel_id)
{
    struct icc_channel_vector *vector = NULL;

    if ((GET_CHN_ID(channel_id) >= ICC_CHN_ID_MAX) || (!g_icc_ctrl.channels[GET_CHN_ID(channel_id)]) ||
        (GET_FUNC_ID(channel_id) >= g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->func_size)) {
        icc_print_error("para err,chan_id=0x%x\n", channel_id);
        return ICC_INVALID_PARA;
    }

    vector = &(g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->vector[GET_FUNC_ID(channel_id)]);
    if (!vector) { /*lint !e774 */
        icc_print_error("vector NULL\n");
        return ICC_NULL_PTR;
    }

    vector->read_cb = NULL;
    vector->read_context = NULL;
    vector->write_cb = NULL;
    vector->write_context = NULL;

    return ICC_OK;
}

s32 bsp_icc_send(u32 cpuid, u32 channel_id, u8 *data, u32 data_len)
{
    if (((cpuid >= ICC_CPU_MAX) || (cpuid == ICC_THIS_CPU)) || (GET_CHN_ID(channel_id) >= ICC_CHN_ID_MAX) ||
        (!g_icc_ctrl.channels[GET_CHN_ID(channel_id)]) ||
        (GET_FUNC_ID(channel_id) >= g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->func_size) || data == NULL ||
        (data_len >=
        g_icc_ctrl.channels[GET_CHN_ID(channel_id)]->fifo_send->size - sizeof(struct icc_channel_packet))) {
        icc_print_error("para err,cpuid=0x%x, chan_id=0x%x, data=%p, data_len=0x%x\n", cpuid, channel_id, data,
            data_len);
        return ICC_INVALID_PARA;
    }
    return data_send(cpuid, channel_id, data, data_len);
}

s32 bsp_icc_read(u32 channel_id, u8 *buf, u32 buf_len)
{
    u32 read_len = 0;
    s32 ret = ICC_OK; /*lint !e14 */
    u32 real_channel_id = GET_CHN_ID(channel_id);
    u32 func_id = GET_FUNC_ID(channel_id);
    if ((!buf) || (real_channel_id >= ICC_CHN_ID_MAX) || (!g_icc_ctrl.channels[real_channel_id]) ||
        (func_id >= g_icc_ctrl.channels[real_channel_id]->func_size)) {
        icc_print_error("real_channel_id:0x%x，func_id:0x%x.\n", real_channel_id, func_id);
        return ICC_INVALID_PARA;
    }

    irq_lock();
    /* fifo中消息不完整 */
    if (fifo_read_space_get(g_icc_ctrl.channels[real_channel_id]->fifo_recv) >= sizeof(struct icc_channel_packet)) {
        read_len = fifo_get_with_header(g_icc_ctrl.channels[real_channel_id]->fifo_recv, buf, buf_len);
        icc_debug_in_read_cb(channel_id, buf, buf_len, g_icc_ctrl.channels[real_channel_id]->fifo_recv->read,
            g_icc_ctrl.channels[real_channel_id]->fifo_recv->write);
        if (read_len == (u32)ICC_ERR) {
            ret = ICC_INVALID_PARA;
            irq_unlock();
            goto out; /*lint !e801 */
        }
    }
    irq_unlock();
    ret = (s32)read_len;

    return ret;

out:
    icc_print_error("errno=0x%x,buffer=%p,len%d,read_len%d\n", ret, buf, buf_len, read_len);

    return ret;
} /*lint -restore +e732 */
