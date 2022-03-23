/*
 * Copyright @ Huawei Technologies Co., Ltd. 2019-2028. All rights reserved.
 * Description: secure mem common header file
 * Create: 2019-06-29
 */

#ifndef __SEC_COMMON_H__
#define __SEC_COMMON_H__

/* HIAI_TA:TEE_SERVICE_HIAI
 * UUID f4a8816d-b6fb-4d4f-a2b9-7dae573313c0
 */
#define HIAI_UUID \
{ \
	0xf4a8816d, \
	0xb6fb, \
	0x4d4f, \
	{ \
		0xa2, 0xb9, 0x7d, 0xae, 0x57, 0x33, 0x13, 0xc0 \
	} \
}

/* HIAI_TA_TINY:TEE_SERVICE_AI_SURITY
 * UUID c123c643-5b5b-4c9f-9098-bb09564d6eda
 */
#define HIAI_TINY_UUID \
{ \
	0xc123c643, \
	0x5b5b, \
	0x4c9f, \
	{ \
		0x90, 0x98, 0xbb, 0x09, 0x56, 0x4d, 0x6e, 0xda \
	} \
}

/* TUI_TA:TEE_SERVICE_TUI
 * UUID 00d73863-69b0-4c8c-9a7d-95585bb78bd2
 */
#define TUI_UUID \
{ \
	0x00d73863, \
	0x69b0, \
	0x4c8c, \
	{ \
		0x9a, 0x7d, 0x95, 0x58, 0x5b, 0xb7, 0x8b, 0xd2 \
	} \
}

/* task_secisp
 * UUID dca5ae8a-769e-4e24-896b-7d06442c1c0e
 */
#define SEC_ISP_UUID \
{ \
	0xdca5ae8a, \
	0x769e, \
	0x4e24, \
	{ \
		0x89, 0x6b, 0x7d, 0x06, 0x44, 0x2c, 0x1c, 0x0e \
	} \
}

/* task_secivp
 * UUID 5700f837-8b8e-4661-800b-42bb3fc3141f
 */
#define SEC_IVP_UUID \
{ \
	0x5700f837, \
	0x8b8e, \
	0x4661, \
	{ \
		0x80, 0x0b, 0x42, 0xbb, 0x3f, 0xc3, 0x14, 0x1f \
	} \
}

/* TEE_SERVICE_FACE_REC
 * UUID e8014913-e501-4d44-a9d6-058ec3b93b90
 */
#define SEC_FACE_UUID \
{ \
	0xe8014913, \
	0xe501, \
	0x4d44, \
	{ \
		0xa9, 0xd6, 0x05, 0x8e, 0xc3, 0xb9, 0x3b, 0x90 \
	} \
}

/* TEE_SERVICE_FACE3D_AE_AC
 * UUID d77c4d60-d279-4425-afa8-7f94559eae16
 */
#define SEC_FACE3D_AE_AC_UUID \
{ \
	0xd77c4d60, \
	0xd279, \
	0x4425, \
	{ \
		0xaf, 0xa8, 0x7f, 0x94, 0x55, 0x9e, 0xae, 0x16 \
	} \
}

/* TEE_SERVICE_SECBOOT
 * UUID 08080808-0808-0808-0808-080808080808
 */
#define SECBOOT_UUID \
{ \
	0x08080808, \
	0x0808, \
	0x0808, \
	{ \
		0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 \
	} \
}

/* EID_1:TEE_SECIDENTIFICATION1 (26MB version)
 * UUID 8780dda1-a49e-45f4-9697-c7ed9e385e83
 */
#define EID1_UUID \
{ \
	0x8780dda1, \
	0xa49e, \
	0x45f4, \
	{ \
		0x96, 0x97, 0xc7, 0xed, 0x9e, 0x38, 0x5e, 0x83 \
	} \
}

/* EID_3:TEE_SECIDENTIFICATION3 (3MB version)
 * UUID 335129cd-41fa-4b53-9797-5ccb202a52d4
 */
#define EID3_UUID \
{ \
	0x335129cd, \
	0x41fa, \
	0x4b53, \
	{ \
		0x97, 0x97, 0x5c, 0xcb, 0x20, 0x2a, 0x52, 0xd4 \
	} \
}

/* ION
 * UUID f8028dca-aba0-11e6-80f5-76304dec7eb7
 */
#define ION_UUID \
{ \
	0xf8028dca, \
	0xaba0, \
	0x11e6, \
	{ \
		0x80, 0xf5, 0x76, 0x30, 0x4d, 0xec, 0x7e, 0xb7 \
	} \
}

/* VLTMM
 *  * UUID d902f26f-7153-4e46-a79c94844af8b007
 *   */
#define VLTMM_UUID \
{ \
    0xd902f26f, \
    0x7153, \
    0x4e46, \
    { \
            0xa7, 0x9c, 0x94, 0x84, 0x4a, 0xf8, 0xb0, 0x07 \
        } \
}

#define GTASK_UUID \
{ \
    0x00000000, \
    0x0000, \
    0x0000, \
    { \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    } \
}

int ddr_unset_sec_for_ta_crash(struct sglist *sglist, int feature_id);

#endif
