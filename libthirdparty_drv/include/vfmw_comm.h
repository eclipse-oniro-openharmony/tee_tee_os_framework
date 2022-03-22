/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2005-2011. All rights reserved.
 * Description: Vdec firmware common types
 * Author: yangyichang
 * Create: 2005-11-26
 */
#ifndef __VDEC_FIRMWARE_COMM_H__
#define __VDEC_FIRMWARE_COMM_H__

#include "vfmw_comm_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EXIT_NORMAL = 1,
    EXIT_ABNORMAL
} VdecExitType;

/* formal definition, to be removed later */
#define MAX_TMPBUF_SIZE         (128)

/* extream value */
#define MAX_USRDAT_SIZE         (1024)

#define MAX_HDR_DYN_MTDT_SIZE   (128)

/* PLUS_FS_NUM = DecFsNum - MaxRefFsNum */
#define MAX_FRAME_NUM           (32)

#define CHECK_COND_RETURN_VALUE(condition, retVal) \
    do { \
        if (condition) { \
            dprint(PRN_ERROR, "check(%d) error", condition); \
            return (retVal); \
        } \
    } while (0)

/* buffer flags bits masks omx buffer flag. */
#define VDEC_BUFFERFLAG_EOS             (0x00000001)
#define VDEC_BUFFERFLAG_STARTTIME       (0x00000002)
#define VDEC_BUFFERFLAG_DECODEONLY      (0x00000004)
#define VDEC_BUFFERFLAG_DATACORRUPT     (0x00000008)
#define VDEC_BUFFERFLAG_ENDOFFRAME      (0x00000010)
#define VDEC_BUFFERFLAG_SYNCFRAME       (0x00000020)
#define VDEC_BUFFERFLAG_EXTRADATA       (0x00000040)
#define VDEC_BUFFERFLAG_CODECCONFIG     (0x00000080)
/* channel capacity level */
typedef enum HiCapLevelE {
    CAP_LEVEL_MPEG_QCIF = 0,
    CAP_LEVEL_MPEG_CIF,
    CAP_LEVEL_MPEG_D1,
    CAP_LEVEL_MPEG_720,
    CAP_LEVEL_MPEG_FHD,
    CAP_LEVEL_H264_QCIF,
    CAP_LEVEL_H264_CIF,
    CAP_LEVEL_H264_D1,
    CAP_LEVEL_H264_720,
    CAP_LEVEL_H264_FHD,
    CAP_LEVEL_H264_BYDHD,

    CAP_LEVEL_1280_X_800,
    CAP_LEVEL_800_X_1280,
    CAP_LEVEL_1488_X_1280,
    CAP_LEVEL_1280_X_1488,
    CAP_LEVEL_2160_X_1280,
    CAP_LEVEL_1280_X_2160,
    CAP_LEVEL_2160_X_2160,
    CAP_LEVEL_4096_X_2160,
    CAP_LEVEL_2160_X_4096,
    CAP_LEVEL_4096_X_4096,
    CAP_LEVEL_8192_X_4096,
    CAP_LEVEL_4096_X_8192,
    CAP_LEVEL_8192_X_8192,

    CAP_LEVEL_SINGLE_IFRAME_FHD,
    CAP_LEVEL_USER_DEFINE_WITH_OPTION,

    CAP_LEVEL_MVC_FHD,
    CAP_LEVEL_HEVC_QCIF,
    CAP_LEVEL_HEVC_CIF,
    CAP_LEVEL_HEVC_D1,
    CAP_LEVEL_HEVC_720,
    CAP_LEVEL_HEVC_FHD,
    CAP_LEVEL_HEVC_UHD,

    CAP_LEVEL_BUTT
} VdecChanCapLevelE;

typedef enum {
    DEC_FRAME_NUM_POS = 0,
    DEC_FRAME_SIZE_POS,
    DEC_PMV_SIZE_POS,
    DEC_DEC_WIDTH_POS,
    DEC_DEC_HEIGHT_POS,
    DEC_STRIDE_POS,
    DEC_DISP_WIDTH_POS,
    DEC_DISP_HEIGHT_POS,
    DEC_BIT_DEPTH_POS,
    DEC_BUTT,
} EventNeedArrangeParamImdex;

/* VDEC control command id, different function have different CID. */
typedef enum HiVdecCidE {
    VDEC_CID_GET_GLOBAL_STATE = 0,     /* 0. get global state */
    VDEC_CID_GET_CAPABILITY,           /* 1. get the capacity of the decoder */
    VDEC_CID_GET_GLOBAL_CFG,           /* 2. get the configured info of the decoder */
    VDEC_CID_CFG_DECODER,              /* 3. congfig the decoder */
    VDEC_CID_CREATE_CHAN,              /* 4. create channel */
    VDEC_CID_CREATE_CHAN_WITH_OPTION,  /* 5. create channel with options */
    VDEC_CID_DESTROY_CHAN,             /* 6. destroy channel */
    VDEC_CID_DESTROY_CHAN_WITH_OPTION, /* 7. destroy a channel created with options */
    VDEC_CID_GET_CHAN_CFG,             /* 8. get the configuration of the decode channel */
    VDEC_CID_CFG_CHAN,                 /* 9. config the decode channel */

    VDEC_CID_GET_CHAN_STATE = 10,        /* 10. get the state of the decode channel */
    VDEC_CID_START_CHAN,               /* 11. start channel */
    VDEC_CID_STOP_CHAN,                /* 12. stop channel */
    VDEC_CID_RESET_CHAN,               /* 13. reset channel */
    VDEC_CID_SET_STREAM_INTF,          /* 14. set the stream access interface for the decode channel */
    VDEC_CID_GET_IMAGE_INTF,           /* 15. get the stream access interface for the decode channel */
    VDEC_CID_GET_STREAM_SIZE,          /* 16. get the stream size(in byte) held by vfmw */
    VDEC_CID_GET_HAL_MEMSIZE,          /* 17. get the memory budget for hal usage */
    VDEC_CID_GET_CHAN_MEMSIZE,         /* 18. get the memory budget for the specified channel capacity level */
    VDEC_CID_GET_CHAN_DETAIL_MEMSIZE_WITH_OPTION,  /* 19. get the detailed memory budget according to the options */

    VDEC_CID_GET_CHAN_MEMADDR = 20,      /* 20. get chan mem addr */
    VDEC_CID_GET_CHAN_ID_BY_MEM,       /* 21. querry the channel number according the memroy physical address */
    VDEC_CID_RELEASE_STREAM,           /* 22. reset scd to release stream buffers */
    VDEC_CID_RESET_CHAN_WITH_OPTION,   /* 23. reset channel with options to keep some characters of the channel */
    VDEC_CID_CFG_EXTRA,                /* 24. set decoder's extra_ref & extra_disp */

    VDEC_CID_GET_USRDEC_FRAME = 30,      /* 30 for VFMW_USER channel, get a frame block from vfmw */
    VDEC_CID_PUT_USRDEC_FRAME,         /* 31 for VFMW_USER channel, push a frame(info) into vfmw */
    VDEC_CID_SET_DISCARDPICS_PARAM,    /* 32 get discard pictures parameters */
    VDEC_CID_SYNC_EXT_BUFFER,          /* 33 synchronize ext buffer state */

    VDEC_CID_SET_DBG_OPTION = 40,        /* 40 set debug options */
    VDEC_CID_GET_DGB_OPTION,           /* 41 get debug options */
    VDEC_CID_SET_PTS_TO_SEEK,          /* 42 set pts to be seeked by vfmw */
    VDEC_CID_SET_TRICK_MODE,           /* 44 set fast forward or backword speed */
    VDEC_CID_SET_CTRL_INFO,           /* 45 set pvr fast forward or backword stream info and control info */
    VDEC_CID_SET_FRAME_RATE,           /* 46 set frame rate to vfmw */
    VDEC_CID_START_LOWDLAY_CALC,       /* 47 start lowdelay performance calculation */
    VDEC_CID_STOP_LOWDLAY_CALC,        /* 48 stop  lowdelay performance calculation */

    VDEC_CID_ALLOC_MEM_TO_CHANNEL = 50,  /* 50 alloc entir mem for vfmw */
    VDEC_CID_BIND_MEM_TO_CHANNEL,      /* 51 alloc seperate mem and bind to vfmw */
    VDEC_CID_ACTIVATE_CHANNEL,         /* 52 notify vfmw that mem already in position */
    VDEC_CID_SET_FRAME_RATE_TYPE,      /* 53 set frmae type */
    VDEC_CID_WAKEUP_THREAD,
    VDEC_CID_GET_FREQ_PARAM,
} VdecCidE;

/* buffer callbak type */
typedef enum {
    BC_CHK_BUF = 0,
    BC_REPORT_BUF,
} VdecBcTypeE;


/* adapter type */
typedef enum {
    ADAPTER_TYPE_VDEC = 0,
    ADAPTER_TYPE_OMXVDEC,
    ADAPTER_TYPE_BUTT,
} VdecAdapterTypeE;

/* channel purpose */
typedef enum {
    PURPOSE_DECODE = 1,
    PURPOSE_FRAME_PATH_ONLY,
    PURPOSE_BUTT
} VdecChanPurposeE;

/* channel memory allocation type */
typedef enum {
    MODE_ALL_BY_SDK = 1,
    MODE_ALL_BY_MYSELF,
    MODE_PART_BY_SDK,
    MODE_BUTT,
} VdecChanMemAllocModeE;

/* memory type */
typedef enum {
    MEM_ION = 0,      // ion default
    MEM_ION_CTG,      // ion contigeous
    MEM_CMA,          // kmalloc
    MEM_CMA_ZERO,     // kzalloc
} MemTypeE;

/* ext buf state */
typedef enum {
    EXTBUF_NULL = 0,       // ext buf not exist / or deleted
    EXTBUF_INSERT,         // ext buf first inserted
    EXTBUF_QUEUE,          // ext buf in queue
    EXTBUF_TAKEN,          // ext buf already taken
    EXTBUF_DEQUE,          // ext buf out queue
} ExtBufStateE;


typedef enum {
#ifdef LOWER_FREQUENCY_SUPPORT
    VDEC_CLK_RATE_LOWER = 0,
#endif
    VDEC_CLK_RATE_LOW,
    VDEC_CLK_RATE_NORMAL,
    VDEC_CLK_RATE_HIGH,
    VDEC_CLK_RATE_MAX,
} ClkRateE;

typedef union {
    struct {
        SINT32 isAdvProfile;
        SINT32 codecVersion;
    } vc1Ext;

    struct {
        /* if the image need to be reversed, set to 1, otherwise set to 0 */
        SINT32 bReversed;
    } vp6Ext;
} StdExtensionU;
/* decode mode */
typedef enum {
    IPB_MODE = 0,
    IP_MODE,
    I_MODE,
    DISCARD_MODE,
    DISCARD_B_BF_P_MODE    /* discard B before get first P */
} DecModeE;


/* channel config info */
typedef struct {
    /* support stream of all p frames */
    SINT8            supportAllP;
    /* module lowdelay enable */
    SINT8            moduleLowlyEnable;
    /* specify for omx path */
    SINT8            isOmxPath;
    /* special mode switch, bit 0: CRC check */
    SINT8            specMode;
    /* 0: uv, 1: vu */
    UINT8            uvOrder;
    /* 0: output by display order, 1:output by decode order */
    SINT8            decOrderOutput;
    /* lowdly enable */
    SINT8            lowdlyEnable;
    /* frame compress enable */
    SINT8            vcmpEn;
    /* water marker enable */
    SINT8            wmEn;
    /* decode mode, 0: IPB, 1: IP, 2: I */
    DecModeE         decMode;
    /* video compressing standard */
    SINT32           eVidStd;
    /* channel priority */
    SINT32           chanPriority;
    /* channel error torlerance threshold.
     * 0  : zero torlerance;
     * 100: display no matter how many error occured
     */
    UINT32           chanErrThr;
    /* stream overflow control threshold, must >= 0,
     * 0 means do not enable overflow control
     */
    SINT32           chanStrmOfThr;
    /* water marker start line number */
    SINT32           vcmpWmStartLine;
    /* water marker end line number */
    SINT32           vcmpWmEndLine;
    /* omx path ext packet num */
    SINT32           maxRawPacketNum;
    /* omx path ext packet size */
    SINT32           maxRawPacketSize;
    /* for CSD PATHMODE */
    SINT32           pathMode;
    /* for CSD FrameRate */
    UINT32           frameRate;
    /* video Vilte Mode add for CSD */
    UINT32           videoScenario;
    /* extended info, for VC1 indicate AP or not, and other version info */
    StdExtensionU    stdExt;
    /* gpu version */
    UINT32           gpuVersion;
    SINT8            isTvp;
    UINT8            oiooDebug;
} VdecChanCfgS;

typedef struct {
    UINT32 lowerLimitOfHighFreq;
    UINT32 lowerLimitOfNormFreq;
    UINT32 lowerLimitOfLowFreq;
} VdecFreqParam;

typedef struct {
    UINT16 displayPrimariesX[3]; // 3: Rgb three primary colors
    UINT16 displayPrimariesY[3]; // 3: Rgb three primary colors
    UINT16 whitePointX;
    UINT16 whitePointY;
    UINT32 MaxDisplayMasteringLuminance;
    UINT32 MinDisplayMasteringLuminance;
} MasteringDisplayColourVolumeS;


/* REAL usr decode pic header */
typedef struct {
    UINT32 picFlag;
    UINT32 picCodType;
    UINT32 picWidthInPixel;
    UINT32 picHeightInPixel;
    UINT32 trb;
    UINT32 trd;
    UINT32 rounding;
    UINT32 totalSliceNum;
} CbPicHdrEncS;

/* REAL usr decode slice header */
typedef struct {
    UINT32 slcFlag;
    UINT32 sliceQp;
    UINT32 osvquant;
    UINT32 dblkFilterPassThrough;
    UINT32 firstMbInSlice;
    UINT32 bitOffset;
    UINT32 bitLen;
    UINT32 reserve;
} CbSlcHdrEncS;

/* memroy description */
typedef struct {
    UINT8      isSecure;
    MemTypeE   memType;
    UADDR      phyAddr;
    UINT32     length;
    HI_VOID    *virAddr;
    SINT32     shareFd;
} MemDescS;

/* detailed channel memory desc. */
typedef struct {
    MemDescS chanMemVdh;
    MemDescS chanMemScd;
    MemDescS chanMemCtx;
    MemDescS totalMem;
} VdecChanMemDetailS;

/* For dynamic frame store param */
typedef struct {
    UADDR  phyAddr;
    UINT64 needMMZ;
    UINT32 frameNum;
    UINT32 length;
    UINT64 virAddr;
} VdecChanFrameParamS;

/* memroy description */
typedef struct {
    UADDR  frmPhyAddr;
    UADDR  hfbcHeaderYOffset;
    UADDR  hfbcPayloadYOffset;
    UADDR  hfbcHeaderUvOffset;
    UADDR  HfbcPayloadUVOffset;
    UINT32 scrambleMode;
    UADDR  pmvPhyAddr;
    UINT32 frmLength;
    UINT32 pmvLength;
    UINT64 frmVirAddr;      /* Set this member UINT64, for compatible between 32 & 64 system */
    UINT64 pmvVirAddr;      /* Set this member UINT64, for compatible between 32 & 64 system */
    SINT32 pmvShareFd;
    SINT32 frmShareFd;
} VdecChanFrameNode;

/* For dynamic seperated frame store param */
typedef struct {
    UINT32               totalFrameNum;
    UINT32               isHfbc;
    VdecChanFrameNode node[MAX_FRAME_NUM];
    bool isTvp;
} VdecChanFrameStoreS;

/* user defined channel option */
typedef struct {
    /* channel type vdec/omxvdec */
    VdecAdapterTypeE eAdapterType;
    /* channel purpose, indicate if this channel is used for decoding or frame path only */
    VdecChanPurposeE purpose;
    /* who alloc memory for the channel */
    VdecChanMemAllocModeE memAllocMode;
    /* max width  supported by the channel */
    SINT32 maxWidth;
    /* max height supported by the channel */
    SINT32 maxHeight;
    /* for H264,H265 max slice number */
    SINT32 maxSliceNum;
    /* for H264,H265 max vps number */
    SINT32 maxVpsNum;
    /* for H264,H265 max sps number */
    SINT32 maxSpsNum;
    /* for H264,H265 max pps number */
    SINT32 maxPpsNum;
    /* max reference frame num */
    SINT32 maxRefFrameNum;
    /* if support B frame. 1: yes, 0: no */
    SINT32 supportBFrame;
    /* if this channel support H.264/MVC/H.265 decoding. bit 0:h264, 1:mvc, 2:h265 */
    UINT32 supportStd;
    /* if this channel support scd lowdly. 1: yes, 0: no */
    SINT32 scdLowdlyEnable;
    /* when resolution change, if the framestore be re-partitioned according to the new resolution. */
    /* 1:yes. can decode smaller(but more ref) stream, but one or more frame may be discarded */
    /* 0:no.  no frame discarded, but the stream with more ref can not dec, even if the total memory is enough */
    SINT32 reRangeEn;
    /* SCD buf size */
    SINT32 scdBufSize;
    /* user defined display frame num */
    SINT32 displayFrameNum;
    /* if purpose==PURPOSE_FRAME_PATH_ONLY, frame store width */
    SINT32 slotWidth;
    /* if purpose==PURPOSE_FRAME_PATH_ONLY, frame store height */
    SINT32 slotHeight;
    /* for dynamic fs control, 1 enable, 0 disable */
    UINT32 dynamicFrameStoreAllocEn;
    /* for dynamic fs self alloc time out */
    SINT32 delayTime;
    /* for omx specific bypass mode */
    UINT32 omxBypassMode;
    /* secure channel flag */
    UINT32 isSecMode;
    /* open fd */
    SINT32 openFd;
    VdecChanMemDetailS memDetail;
    SINT32 eVidStd;
} VdecChanOptionS;

/* user defined channel reset option */
typedef struct {
    SINT32 keepBs;                          /* keep bs in the scd buffer */
    SINT32 keepSpsPps;                      /* keep global info in ctx for seek reset, default 0 */
    SINT32 keepFsp;                         /* keep info in fsp for seek reset, default 0 */
} VdecChanResetOptionS;

typedef struct {
    SINT32 vdhDetailMem;
    SINT32 scdDetailMem;
    SINT32 ctxDetailMem;
    SINT32 totalMemSize;
} DetaliMemSize;

typedef struct {
    ExtBufStateE  state;
    UADDR         phyAddr;
    SINT32        shareFd;
} ExtBufParamS;

/* Ext interface */
typedef SINT32 (*ExtFnEventCallback)(SINT32, SINT32, const VOID*, UINT32);
typedef SINT32 (*ExtFnBufferCallback)(SINT32, SINT32, const VOID*);
#ifdef ENV_SOS_KERNEL
typedef SINT32 (*ExtFnMemMalloc)(SINT8*, UINT32, UINT32, UINT32, VOID*);
#else
typedef SINT32 (*ExtFnMemMalloc)(SINT8*, UINT32, UINT32, VOID*);
#endif
typedef VOID   (*ExtFnMemFree)(VOID*);
typedef SINT32 (*ExtFnPowerOn)(VOID);
typedef SINT32 (*ExtFnPowerOff)(VOID);
typedef SINT32 (*ExtFnGetClkRate)(const ClkRateE*, SINT32);
typedef SINT32 (*ExtFnSetClkRate)(ClkRateE, SINT32);

#ifdef ENV_SOS_KERNEL
enum {
    FN_EVENT_CALLBACK_ID,
    FN_BUFFER_CALLBACK_ID,
    FN_READ_STREAM_ID,
    FN_RELEASE_STREAM_ID,
    FN_INVALID
};
#endif

/* callback interface */
/* NOTICE: NOT allow used in secure world for different size */
typedef struct {
    ExtFnEventCallback  eventHandler;
    ExtFnBufferCallback bufferHandler;
    ExtFnMemMalloc      memMalloc;
    ExtFnMemFree        memFree;
    ExtFnPowerOn        powerOn;
    ExtFnPowerOff       powerOff;
    ExtFnGetClkRate     getClkRate;
    ExtFnSetClkRate     setClkRate;
} InitIntfS;

/* external specified operations(method) */
typedef struct {
    UINT8 isSecure;
    VdecAdapterTypeE adapterType;
    MemDescS extHalMem;
    InitIntfS extIntf;
} VdecOperationS;

typedef enum {
    FRAME_PACKING_TYPE_NONE,             /* normal frame, not a 3D frame */
    FRAME_PACKING_TYPE_SIDE_BY_SIDE,     /* side by side */
    FRAME_PACKING_TYPE_TOP_BOTTOM,       /* top bottom */
    FRAME_PACKING_TYPE_TIME_INTERLACED,  /* time interlaced: one frame for left eye, the next frame for right eye */
    FRAME_PACKING_TYPE_BUTT
} FramePackingTypeE;

typedef enum {
    USD_INVALID = 0,
    USD_MP2SEQ,
    USD_MP2GOP,
    USD_MP2PIC,
    USD_MP4VSOS,
    USD_MP4VSO,
    USD_MP4VOL,
    USD_MP4GOP,
    USD_H264,
    USD_AVSSEQ,
    USD_AVSPIC
} VdecUsdTypeE;

/* userdata desc. */
typedef struct {
    UINT8  data[MAX_USRDAT_SIZE]; /* UsrDat data entity */
    UINT8  picCodingType;
    UINT8  topFieldFirst;

    /* for CC, valid when isRegistered=1 */
    SINT8  isRegistered;
    UINT8  ituTT35CountryCode;
    UINT8  ituTT35CountryCodeExtensionByte;
    UINT16 ituTT35ProviderCode;
    UINT32 picNumCount;
    UINT32 dnrUsedFlag;         /* internal used only, ignore */
    VdecUsdTypeE from;          /* UsrDat source */
    UINT32 seqCnt;              /* to be removed later */
    UINT32 seqImgCnt;
    SINT32 dataSize;            /* UsrDat size, in byte */
    UINT64 pts;                 /* pts of the frame containning the userdata */
} VdecUsrDatS, UsrDat;

typedef struct {
    UINT32 isHdrAvailable;
    UINT32 hdrType;
    UINT32 hdrMtdtSize;
    UINT8  hdrMtdt[MAX_HDR_DYN_MTDT_SIZE];
} ImageHdrPlusInfo;

/* decoded image description */
typedef struct {
    UINT32 aspectWidth;
    UINT32 aspectHeight;

    UINT32 dispEnableFlag;
    UINT32 dispFrameDistance;
    UINT32 distanceBeforeFirstFrame;
    UINT32 gopNum;
    UINT32 repeatCnt;

    UINT32 isCurLast;     // current last frame in queue
    UINT32 isFldSave;     // 0:frm, 1:fld
    UINT32 topFldType;
    UINT32 bottomFldType;

    /* [1:0]   frame_type: 00(I), 01(P), 10(B), 11(Reserved)
     * [4:2]   CSP: 000(YUV:4:2:0), 001(YUV:4:0:0), 010~111(Reserved)
     * [7:5]   Norm: 000(component), 001(PLA), 010(NTSC), 011(SECAM), 100(MAC),
     *         101(Unspecified Video format), 110~111(Reserved)
     * [9:8]   source_format: 00(progressive), 01(interlaced), 10(infered_progressive), 11(infered_interlaced)
     * [11:10] field_valid_flag: 00(top_field invalid, bottom_field invalid), 01(top_field valid, bottom_field invalid),
     *         10(top_field invalid, bottom_field valid), 11(top_field valid, bottom_field valid)
     * [13:12] topFieldFirst: 00(bottom field first), 01(top field first), 10(un-know), 11(Reserved)
     * [16:14] aspectRatio: 000(unspecified), 001(4:3), 010(16:9), 011(2.21:1),100(2.35:1),
     *         101(origin width and height), 111(Reserved)
     * [30:17] (Reserved)
     * [31]    ajust yuv bit, 1 enable, 0 disable (in param)
     */
    UINT32 format;
    UINT32 imageWidth;
    UINT32 imageHeight;
    UINT32 dispWidth;
    UINT32 dispHeight;
    UINT32 dispCenterX;
    UINT32 dispCenterY;

    UINT32 frameRate;      /* frame rate, in Q10 */
    UINT32 imageStride;
    UINT32 imageId;
    UINT32 errorLevel;
    UINT32 seqCnt;
    UINT32 seqImgCnt;

    UINT32 bitDepthLuma;
    UINT32 bitDepthChroma;
    UINT32 frameNum;
    SINT32 lastFrame;
    SINT32 viewId;         // h264 mvc
    SINT32 imageId1;
    UINT32 is3d;
    UINT32 isCompress;
    UINT32 isSecure;
    FramePackingTypeE eFramePackingType;

    SINT32 shareFd;
    UADDR topLumaPhyAddr;
    UADDR topChromPhyAddr;
    UADDR btmLumaPhyAddr;
    UADDR btmChromPhyAddr;
    UADDR topLumaPhyAddr1;
    UADDR topChromPhyAddr1;
    UADDR btmLumaPhyAddr1;
    UADDR btmChromPhyAddr1;

    UADDR lumaPhyAddr;
    UADDR chromPhyAddr;
    UADDR luma2dPhyAddr;
    UADDR chrom2dPhyAddr;
    UADDR lineNumPhyAddr;

    UINT32 leftOffset;
    UINT32 rightOffset;
    UINT32 topOffset;
    UINT32 bottomOffset;

    UINT32 actualCRC[2]; // 2: Top and bottom fields

    UINT64 srcPts;
    UINT64 pts;
    UINT64 userTag;
    UINT64 dispTime;
    UINT32 uvStride;
    UINT32 headStride;
    UADDR  headLumaPhyAddr;
    UADDR  headChromPhyAddr;
    VdecUsrDatS *usrDat[4];   // NOTICE!!! in tvp path, these member invalid for 32 & 64 system difference
#ifdef ENV_SOS_KERNEL
    /* For upper pointer, make struct with same size between 62bit normal and 32bit secure world */
    UINT32 reserve[4];  // 4: usr dat index, with same index with  usrDat
#endif
    ImageHdrPlusInfo hdrPlusInfo;
} Image;

/* Export image interface */
/* Export image interface */
typedef SINT32(*ExtFnReadImage) (SINT32, Image *);
typedef SINT32(*ExtFnReleaseImage) (SINT32, Image *);

/* image accessing interface */
/* NOTICE: NOT allow used in secure world for different size */
typedef struct {
    SINT32             imageProviderInstId;
    ExtFnReadImage     readImage;
    ExtFnReleaseImage  releaseImage;
} ImageIntfS;

typedef struct {
    UINT8  isSeekPending;
    UINT32 flags;
    UINT32 bufLen;
    UINT32 cfgWidth;
    UINT32 cfgHeight;
} RawExtensionS;

/* stream packet struct */
typedef struct {
    UINT8   isNotLastPacketFlag;
    UINT8   isStreamEndFlag;
    SINT32  length;
    UINT32  index;
    UINT32  discontinueCount;
    UINT32  dispEnableFlag;
    UINT32  dispFrameDistance;
    UINT32  distanceBeforeFirstFrame;
    UINT32  gopNum;
    UADDR   phyAddr;
    HI_VOID *virAddr;
    SINT32  shareFd;
    UINT64  userTag;
    UINT64  dispTime;
    UINT64  pts;
    RawExtensionS rawExt;         /* Omx raw buffer extension */
    SINT32  bufferId;
} StreamDataS;

/* Ext stream interface */
typedef SINT32(*ExtFnReadSteam) (SINT32, StreamDataS *);
typedef SINT32(*ExtFnReleaseStream) (SINT32, StreamDataS *);

/* stream accessing interface */
/* NOTICE: NOT allow used in secure world for different size */
typedef struct {
    SINT32 streamProviderInstId;
    ExtFnReadSteam readStream;
    ExtFnReleaseStream releaseStream;
} StreamIntfS;

typedef enum {
    PTS_FRMRATE_TYPE_PTS,         /* use the frame rate calculates from pts */
    PTS_FRMRATE_TYPE_STREAM,      /* use the frame rate comes from stream */
    PTS_FRMRATE_TYPE_USER,        /* use the frame rate set by user */
    PTS_FRMRATE_TYPE_USER_PTS,    /* use the frame rate set by user until the 2nd I frame comes, then use the frame rate calculates from pts */
    PTS_FRMRATE_TYPE_BUTT,
} vfmw_pts_framrate_type;

typedef struct {
    UINT32 fps_integer;        /* integral part of the frame rate (in frame/s) */
    UINT32 fps_decimal;        /* fractional part (calculated to three decimal places) of the frame rate (in frame/s) */
} vfmw_pts_frmrate_value;

typedef struct {
    vfmw_pts_framrate_type  en_frm_rate_type;  /* source of frame rate */
    vfmw_pts_frmrate_value  st_set_frm_rate;   /* setting frame rate */
} vfmw_pts_frmrate;

#ifdef __cplusplus
}
#endif

#endif  // __VDEC_FIRMWARE_H__
