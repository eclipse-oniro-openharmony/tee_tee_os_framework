/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 *  Description: Secure OS SEC IPC Drivers, Send IPC Msg to other Secure Core.
 *  Create: 2019-07-08
 */

#include "ipc_mailbox.h"
#include "register_ops.h"

#define TIME_COUNT_US 3000

static inline void __ipc_set_src_direct(
	unsigned int base, unsigned int src, unsigned int mdev)
{
	writel(src, base + IPCMBxSOURCE(mdev));
}

static inline void __ipc_set_src(
	unsigned int base, unsigned int src, unsigned int mdev)
{
	writel(IPCBITMASK(src), base + IPCMBxSOURCE(mdev));
}

static inline unsigned int __ipc_get_src(unsigned int base, unsigned int mdev)
{
	return readl(base + IPCMBxSOURCE(mdev));
}

static inline void __ipc_set_des(
	unsigned int base, unsigned int src, unsigned int mdev)
{
	writel(IPCBITMASK(src), base + IPCMBxDSET(mdev));
}

static inline unsigned int __ipc_status(unsigned int base, unsigned int mdev)
{
	return readl(base + IPCMBxMODE(mdev));
}

static inline void __ipc_mode(
	unsigned int base, unsigned int mode, unsigned int mdev)
{
	writel(mode, base + IPCMBxMODE(mdev));
}

static inline unsigned int __ipc_cpu_imask_get(
	unsigned int base, unsigned int mdev)
{
	return readl(base + IPCMBxIMASK(mdev));
}

static inline void __ipc_cpu_imask_all(unsigned int base, unsigned int mdev)
{
	writel((~0), base + IPCMBxIMASK(mdev));
}

static inline void __ipc_cpu_imask_clr(
	unsigned int base, unsigned int toclr, unsigned int mdev)
{
	unsigned int reg;

	reg = readl(base + IPCMBxIMASK(mdev));
	reg = reg & (~(toclr));

	writel(reg, base + IPCMBxIMASK(mdev));
}

static inline void __ipc_cpu_iclr(
	unsigned int base, unsigned int clr, unsigned int mdev)
{
	writel(clr, base + IPCMBxICLR(mdev));
}

static inline void __ipc_send(
	unsigned int base, unsigned int tosend, unsigned int mdev)
{
	writel(tosend, base + IPCMBxSEND(mdev));
}

static inline unsigned int __ipc_data_read(
	unsigned int base, unsigned int mdev, unsigned int index)
{
	return readl(base + IPCMBxDATA(mdev, index));
}

static inline void __ipc_data_write(unsigned int base, unsigned int data,
	unsigned int mdev, unsigned int index)
{
	writel(data, base + IPCMBxDATA(mdev, index));
}

static inline void __ipc_unlock(unsigned int base)
{
	writel(IPC_UNLOCK_KEY, base + IPCLOCK());
}

static void ipc_udelay(unsigned int usec)
{
	unsigned int i;

	for (i = 0; i < TIME_COUNT_US * usec; i++) {
		asm("nop");
	}
}

static int find_ipc_index(unsigned int ipc_id, unsigned int mbox_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(g_mbox_irq_table); i++) {
		if ((ipc_id == g_mbox_irq_table[i].ipc_type) &&
			(mbox_id == g_mbox_irq_table[i].mbox_id))
			return i;
	}
	return -EINVAL;
}

static int find_ipc_lock_index(unsigned int ipc_id, unsigned int mbox_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(g_mbox_lock); i++) {
		if ((ipc_id == g_mbox_lock[i].ipc_type) &&
			(mbox_id == g_mbox_lock[i].mbox_id))
			return i;
	}
	return -EINVAL;
}

static void _ipc_mbox_ensure_channel(unsigned int ipc_addr, unsigned int mbox)
{
	unsigned int loop = CHANNEL_TIMEOUT;
	unsigned int status;
	unsigned int src;

	status = __ipc_status(ipc_addr, mbox);

	if (status & IDLE_STATUS)
		return;

	/* src status or dst status, the dst isprocessing, wait here */
	if (!(status & ACK_STATUS)) {
		while (loop != 0) {
			/* loop is 5us * 1000 + 2ms * 40 = 85ms */
			if (loop > CHANNEL_UDELAY_TIME)
				ipc_udelay(5);
			else
				SRE_SwMsleep(2);

			status = __ipc_status(ipc_addr, mbox);
			/* if mbox channel status is ack_status, release mbox */
			if (status & ACK_STATUS)
				break;
			loop--;
		}
		if (loop == 0) {
			IPC_PR_ERR("[0x%x] Mbox[%u] timeout..", ipc_addr, mbox);
			IPC_PR_ERR("DATA0 {0x%x}, DATA1 {0x%x}",
				__ipc_data_read(ipc_addr, mbox, 0),
				__ipc_data_read(ipc_addr, mbox, 1));
		}
		/* whether timeout or not, release mbox */
	}
	/* if status is ack status, just release mailbox */

	/* release mailbox */
	__ipc_cpu_imask_all(ipc_addr, mbox);
	src = __ipc_get_src(ipc_addr, mbox);
	__ipc_set_src_direct(ipc_addr, src, mbox);
}

static int __judge_mbox_status(
	unsigned int ipc_addr, unsigned int mbox_id, unsigned int status)
{
	int retry = 100;

	do {
		if (__ipc_status(ipc_addr, mbox_id) & status)
			break;
		ipc_udelay(100); /* loop is 100, total wait time is 10ms */
		retry--;
	} while (retry);

	if (!retry) {
		IPC_PR_ERR("[0x%x] mbox[%u] status(0x%x) failed!", ipc_addr,
			mbox_id, __ipc_status(ipc_addr, mbox_id));
		return -EINVAL;
	}
	return 0;
}

static int _ipc_hw_send(const struct ipc_msg *msg, unsigned int send_mode)
{
	unsigned int ipc_addr = ipc_baseaddr[msg->ipc_id];
	unsigned int temp, i;
	unsigned int data_len;
	int retry = 100;
	int ret;

	IPC_PR_DEBUG("%s", __func__);

	ret = __judge_mbox_status(ipc_addr, msg->mbox_id, IDLE_STATUS);
	if (ret)
		return ret;

	/* set mailbox src_id */
	__ipc_set_src(ipc_addr, msg->src_id, msg->mbox_id);
	do {
		if (__ipc_get_src(ipc_addr, msg->mbox_id) &
			IPCBITMASK(msg->src_id))
			break;
		ipc_udelay(100); /* loop is 100, total wait time is 10ms */
		retry--;
	} while (retry);

	if (!retry) {
		IPC_PR_ERR("[0x%x] mbox[%u] src set failed!", ipc_addr,
			msg->mbox_id);
		return -EINVAL;
	}

	/* interrupts unmask */
	__ipc_cpu_imask_all(ipc_addr, msg->mbox_id);
	temp = IPCBITMASK(msg->dest_id);
	__ipc_cpu_imask_clr(ipc_addr, temp, msg->mbox_id);

	/* set mbox dest */
	__ipc_set_des(ipc_addr, msg->dest_id, msg->mbox_id);

	/* set mbox mode */
	__ipc_mode(ipc_addr, send_mode, msg->mbox_id);

	/* write mailbox data */
	data_len = (msg->msg_len > MAX_IPC_DATA_LEN) ? MAX_IPC_DATA_LEN
						     : msg->msg_len;
	for (i = 0; i < data_len; i++) {
		__ipc_data_write(
			ipc_addr, msg->ipc_data->data[i], msg->mbox_id, i);
		IPC_PR_DEBUG("IPC send DATA(%u) [0x%08x]", i, msg->ipc_data->data[i]);
	}

	/* enable send */
	__ipc_send(ipc_addr, IPCBITMASK(msg->src_id), msg->mbox_id);
	return 0;
}

static int _ipc_async_config(const struct ipc_msg *msg)
{
	unsigned int ipc_addr = ipc_baseaddr[msg->ipc_id];
	unsigned int ret;

	IPC_PR_DEBUG("%s", __func__);

	/* unlock ipc reg lock */
	__ipc_unlock(ipc_addr);

	/*
	 * to ensure the auto state machine is in the correct state,
	 * if the state is err, wait and release mailbox resource.
	 */
	_ipc_mbox_ensure_channel(ipc_addr, msg->mbox_id);

	ret = _ipc_hw_send(msg, AUTO_ACK_CONFIG);

	/*
	 * async send return directly without waiting for a reply
	 * from the other core
	 */
	return ret;
}

static int _ipc_sync_config(const struct ipc_msg *msg,
	union ipc_data *ack_buffer, unsigned int ack_len)
{
	unsigned int ipc_addr = ipc_baseaddr[msg->ipc_id];
	unsigned int loop = CHANNEL_TIMEOUT;
	unsigned int status;
	unsigned int ret, i;

	IPC_PR_DEBUG("%s", __func__);

	/* unlock ipc reg lock */
	__ipc_unlock(ipc_addr);

	/*
	 * to ensure the auto state machine is in the correct state,
	 * if the state is err, wait and release mailbox resource.
	 */
	_ipc_mbox_ensure_channel(ipc_addr, msg->mbox_id);

	ret = _ipc_hw_send(msg, NORMAL_ACK_CONFIG);
	if (ret)
		return ret;

	/* wait mailbox ack status */
	status = __ipc_status(ipc_addr, msg->mbox_id);
	if (!(status & ACK_STATUS)) {
		while (loop != 0) {
			/* loop is 5us * 1000 + 2ms * 40 = 85ms */
			if (loop > CHANNEL_UDELAY_TIME)
				ipc_udelay(5);
			else
				SRE_SwMsleep(2);

			status = __ipc_status(ipc_addr, msg->mbox_id);
			/* if mbox channel status is ack_status, release mbox */
			if (status & ACK_STATUS)
				break;
			loop--;
		}
		if (loop == 0) {
			IPC_PR_ERR("[0x%x] Mbox[%u] timeout..", ipc_addr,
				msg->mbox_id);
			IPC_PR_ERR("DATA0 {0x%x}, DATA1 {0x%x}",
				__ipc_data_read(ipc_addr, msg->mbox_id, 0),
				__ipc_data_read(ipc_addr, msg->mbox_id, 1));
			ret = -ETIMEOUT;
			goto release;
		}
	}

	/* ACK status, dest answer ipc msg */
	for (i = 0; i < ack_len; i++)
		ack_buffer->data[i] =
			__ipc_data_read(ipc_addr, msg->mbox_id, i);

	/* recover ipc msg with 0 */
	for (i = 0; i < MAX_IPC_DATA_LEN; i++)
		__ipc_data_write(ipc_addr, 0, msg->mbox_id, i);
release:
	/* release mailbox */
	__ipc_cpu_imask_all(ipc_addr, msg->mbox_id);
	__ipc_set_src(ipc_addr, msg->src_id, msg->mbox_id);
	return ret;
}

static void ipc_msg_recv(unsigned int index)
{
	union ipc_data mbox_msg = {{0}};
	unsigned int ipc_type = g_mbox_irq_table[index].ipc_type;
	unsigned int mbox_id = g_mbox_irq_table[index].mbox_id;
	unsigned int ipc_addr = ipc_baseaddr[ipc_type];
	unsigned char module_tag;
	unsigned int i;
	unsigned int toclr, imask;
	unsigned int status;

	IPC_PR_DEBUG("%s", __func__);

	/* read data form mailbox data reg(8 data reg) */
	for (i = 0; i < MAX_IPC_DATA_LEN; i++) {
		mbox_msg.data[i] = __ipc_data_read(ipc_addr, mbox_id, i);
		IPC_PR_DEBUG("IPC recv DATA(%u) [0x%08x]", i, mbox_msg.data[i]);
	}

	module_tag = mbox_msg.cmd_mix.cmd_src;
	IPC_PR_DEBUG("module tag, src[0] 0x%x, dst[1] 0x%x",
		mbox_msg.cmd_mix.cmd_src, mbox_msg.cmd_mix.cmd_obj);

	/* find the module index and callback module's func */
	for (i = 0; i < MAX_ECHO_NUM; i++) {
		if (module_tag == g_mbox_irq_table[index].module_tag[i] &&
			g_mbox_irq_table[index].ipc_notifier[i]) {
			g_mbox_irq_table[index].ipc_notifier[i](&mbox_msg);
			break;
		}
	}

	/* if i = MAX_ECHO_NUM means module_tag has none matching */
	if (i == MAX_ECHO_NUM)
		IPC_PR_ERR("ERR module tag, data[0] 0x%x, data[1] 0x%x",
			mbox_msg.data[0], mbox_msg.data[1]);

	/* clear data */
	for (i = 0; i < MAX_IPC_DATA_LEN; i++)
		__ipc_data_write(ipc_addr, 0, mbox_id, i);

	/* clear irq */
	imask = __ipc_cpu_imask_get(ipc_addr, mbox_id);
	toclr = (IPCBITMASK(g_mbox_irq_table[index].mbox_src_id[0]) |
			IPCBITMASK(g_mbox_irq_table[index].mbox_src_id[1])) & (~imask);
	__ipc_cpu_iclr(ipc_addr, toclr, mbox_id);

	/* send ack if mbox mode is not AUTO_ACK */
	status = __ipc_status(ipc_addr, mbox_id);
	if ((DEST_STATUS & status) && (!(AUTO_ACK_CONFIG & status)))
		__ipc_send(ipc_addr, toclr, mbox_id);
}

static void ipc_interrupt(unsigned int irq)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(g_mbox_irq_table); i++) {
		if (irq == g_mbox_irq_table[i].mbx_irq) {
			/* handle msg and call receive func */
			ipc_msg_recv(i);
			return;
		}
	}
	IPC_PR_ERR("ERROR IPC interrupt num [%u]", irq);
}

int ipc_recv_notifier_register(unsigned int ipc_id, unsigned int mbox_id,
	unsigned char module_tag, const void *notifier)
{
	int ipc_index, lock_index;
	unsigned int i;
	int ret_lock;
	int ret = 0;

	IPC_PR_DEBUG("%s", __func__);

	if (ipc_id >= MAX_IPC_TYPE || !notifier || mbox_id > MAX_MBOX_ID) {
		IPC_PR_ERR("recv notify register input para err!");
		return -EINVAL;
	}

	ipc_index = find_ipc_index(ipc_id, mbox_id);
	lock_index = find_ipc_lock_index(ipc_id, mbox_id);
	if (lock_index < 0 || ipc_index < 0) {
		IPC_PR_ERR("ipc[%d] & mbox[%d] don't exist in table", ipc_id, mbox_id);
		return -EINVAL;
	}

	ret_lock = pthread_mutex_lock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("mbox_irq_table lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	for (i = 0; i < MAX_ECHO_NUM; i++) {
		if ((g_mbox_irq_table[ipc_index].module_tag[i] == 0) &&
			(g_mbox_irq_table[ipc_index].ipc_notifier[i] == NULL)) {
			g_mbox_irq_table[ipc_index].module_tag[i] = module_tag;
			g_mbox_irq_table[ipc_index].ipc_notifier[i] = notifier;
			IPC_PR_DEBUG(
				"ipc register [%u] [0x%x]!", i, module_tag);
			break;
		}
	}

	if (i == MAX_ECHO_NUM) {
		/* couldn't find space to register module notifier */
		ret = -ENOMEM;
		IPC_PR_ERR("ipc register err, thers is no space to register [0x%x]!", module_tag);
	}

	ret_lock = pthread_mutex_unlock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		ret = -EIPC_LOCK;
		IPC_PR_ERR("mbox_irq_table unlock error, ret = 0x%x", ret_lock);
	}
	return ret;
}

int ipc_recv_notifier_unregister(
	unsigned int ipc_id, unsigned int mbox_id, unsigned char module_tag)
{
	int ipc_index, lock_index;
	unsigned int i;
	int ret_lock;
	int ret = 0;

	IPC_PR_DEBUG("%s", __func__);

	if (ipc_id >= MAX_IPC_TYPE || mbox_id > MAX_MBOX_ID) {
		IPC_PR_ERR("recv notify unregister input para err!");
		return -EINVAL;
	}

	ipc_index = find_ipc_index(ipc_id, mbox_id);
	lock_index = find_ipc_lock_index(ipc_id, mbox_id);
	if (lock_index < 0 || ipc_index < 0) {
		IPC_PR_ERR("ipc[%d] & mbox[%d] don't exist in table", ipc_id,
			mbox_id);
		return -EINVAL;
	}

	ret_lock = pthread_mutex_lock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("mbox_irq_table lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	for (i = 0; i < MAX_ECHO_NUM; i++) {
		if (g_mbox_irq_table[ipc_index].module_tag[i] == module_tag) {
			g_mbox_irq_table[ipc_index].module_tag[i] = 0;
			g_mbox_irq_table[ipc_index].ipc_notifier[i] = NULL;
			IPC_PR_DEBUG(
				"ipc unregister [%u] [0x%x]!", i, module_tag);
			break;
		}
	}

	if (i == MAX_ECHO_NUM) {
		/* couldn't find notifier in ipc_notifier array */
		ret = -EINVAL;
		IPC_PR_ERR("ipc recv unregister find err!");
	}

	ret_lock = pthread_mutex_unlock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		ret = -EIPC_LOCK;
		IPC_PR_ERR("mbox_irq_table unlock error, ret = 0x%x", ret_lock);
	}
	return ret;
}

int ipc_async_send(const struct ipc_msg *msg)
{
	int ret, ret_lock;
	int lock_index;

	IPC_PR_DEBUG("%s", __func__);

	if (!msg || (msg->msg_len > MAX_IPC_DATA_LEN) ||
		(msg->ipc_id >= MAX_IPC_TYPE) ||
		(msg->mbox_id >= MAX_MBOX_ID)) {
		IPC_PR_ERR("async error input para!");
		return -EINVAL;
	}

	lock_index = find_ipc_lock_index(msg->ipc_id, msg->mbox_id);
	if (lock_index < 0) {
		IPC_PR_ERR("async error input ipc & mbox ID!");
		return -EINVAL;
	}

	/* wait for mbox_channel mutex lock */
	ret_lock = pthread_mutex_lock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("async lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	ret = _ipc_async_config(msg);

	ret_lock = pthread_mutex_unlock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("async lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	return ret;
}

int ipc_sync_send(const struct ipc_msg *msg, union ipc_data *ack_buffer,
	unsigned int ack_len)
{
	int ret, ret_lock;
	int lock_index;

	IPC_PR_DEBUG("%s", __func__);

	if (!msg || (msg->msg_len > MAX_IPC_DATA_LEN) ||
		(msg->ipc_id >= MAX_IPC_TYPE) || (msg->mbox_id > MAX_MBOX_ID) ||
		(ack_len > MAX_IPC_DATA_LEN) || !ack_buffer) {
		IPC_PR_ERR("sync error input para!");
		return -EINVAL;
	}

	lock_index = find_ipc_lock_index(msg->ipc_id, msg->mbox_id);
	if (lock_index < 0) {
		IPC_PR_ERR("sync error input ipc & mbox ID!");
		return -EINVAL;
	}

	/* wait for mbox_channel mutex lock */
	ret_lock = pthread_mutex_lock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("sync lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	ret = _ipc_sync_config(msg, ack_buffer, ack_len);

	ret_lock = pthread_mutex_unlock(&g_mbox_lock[lock_index].mbox_lock);
	if (ret_lock != SRE_OK) {
		IPC_PR_ERR("sync lock error, ret = 0x%x", ret_lock);
		return -EIPC_LOCK;
	}

	return ret;
}

int ipc_mbx_status_query(unsigned int ipc_id, unsigned int mbox_id)
{
	unsigned int ipc_addr;
	unsigned int ipc_status;

	if ((ipc_id >= MAX_IPC_TYPE) || (mbox_id > MAX_MBOX_ID)) {
		IPC_PR_ERR("status query error!");
		return -EINVAL;
	}
	ipc_addr = ipc_baseaddr[ipc_id];
	ipc_status = __ipc_status(ipc_addr, mbox_id) & IPC_MODE_MASK;
	if ((ipc_status == ACK_STATUS) || (ipc_status == IDLE_STATUS))
		return 0;
	else
		return -EIPCBUSY;
}

int ipc_mailbox_init(void)
{
	unsigned int i, irq, ret;
	pthread_mutex_t *temp = NULL;

	IPC_PR_DEBUG("mailbox init ++");
	/* request irq from ipc_mbox_irq_table */
	for (i = 0; i < ARRAY_SIZE(g_mbox_irq_table); i++) {
		irq = g_mbox_irq_table[i].mbx_irq;
		ret = SRE_HwiCreate((HWI_HANDLE_T)irq, (HWI_PRIOR_T)0,
			(HWI_MODE_T)0, (HWI_PROC_FUNC)ipc_interrupt,
			(HWI_ARG_T)irq);
		if (ret != SRE_OK) {
			/*
			 * some irqs enable err shouldn't affect other
			 * irqs enable
			 */
			IPC_PR_ERR(
				"SRE_HwiCreate irq %u errorNO 0x%x", irq, ret);
			continue;
		}

		ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
		if (ret != SRE_OK) {
			/*
			 * some irqs enable err shouldn't affect other
			 * irqs enable
			 */
			IPC_PR_ERR(
				"SRE_HwiEnable irq %u errorNO 0x%x", irq, ret);
			continue;
		}
	}

	/* init pthread_mutex for common table */
	for (i = 0; i < ARRAY_SIZE(g_mbox_lock); i++) {
		temp = &g_mbox_lock[i].mbox_lock;
		ret = pthread_mutex_init(temp, NULL);
		/* some lock init err shouldn't affect others lock init */
		if (ret != SRE_OK) {
			IPC_PR_ERR("lock init failed! lock_index(%u)-ret:0x%x",
				i, ret);
			continue;
		}
	}

	IPC_PR_DEBUG("mailbox init --");
	return 0;
}

DECLARE_TC_DRV(
	ipc_mailbox_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	ipc_mailbox_init,
	NULL,
	NULL,
	NULL,
	NULL
);
