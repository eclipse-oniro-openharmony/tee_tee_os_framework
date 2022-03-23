  #===============================================================================
# local varible
#===============================================================================
HI_LOC_INCLUDE	+= -I$(HI_LOC_CUR)
HI_LOC_INCLUDE	+= -I$(HI_LOC_CUR)/dfx

#===============================================================================
# target
#===============================================================================
TARGET 		 = hi_sec
$(TARGET)-y += hi_sec_tab_pke_top.o
$(TARGET)-y += hi_sec_pke.o
$(TARGET)-y += dfx/hi_dfx_sec.o
$(TARGET)-y += hi_sec_drv.o
$(TARGET)-y += hi_sec_common.o
$(TARGET)-y += hi_sec_aes.o
$(TARGET)-y += hi_sec_ccm.o
$(TARGET)-y += hi_sec_hash.o
$(TARGET)-y += hi_trng.o
$(TARGET)-y += hi_kdf.o
$(TARGET)-y += hi_sec_rsa.o
$(TARGET)-y += hi_sec_ecdsa.o

include $(HI_LOC_TOP)/module.mk
