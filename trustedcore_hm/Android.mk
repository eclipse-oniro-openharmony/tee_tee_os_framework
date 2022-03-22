define built_trustedcore_image
	TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) make install_headers -j -C $(1)
	TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) make libs ext_libs open_source_libs -j -C $(1)
	TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) make tees -j -C $(1)
	TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) make package -j -C $(1)
	cp $(1)/output/stage/trustedcore.img ${PRODUCT_OUT}
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) -C $(1) clean
endef

define built_trustedcore_image_es
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) chip_type=es OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) BUILD_ES_IMG_WITH_CS=$(BUILD_ES_IMG_WITH_CS) -C $(1)
	cp $(1)/output/stage/trustedcore.img ${PRODUCT_OUT}/trustedcore_es.img
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) chip_type=es OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) BUILD_ES_IMG_WITH_CS=$(BUILD_ES_IMG_WITH_CS) -C $(1) clean
endef

define built_trustedcore_mod
	TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) PRODUCT_OUT=${PRODUCT_OUT} make mods -j -C $(1)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) -C $(1) clean
endef

define prebuild_teeos_clean
	rm -f $(1)tools/linker.lds_pp
endef

define prebuilt_hm_teeos_release
	mkdir -p $(1)/$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) -C $(1) clean O=$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) -C $(1) itrustee_defconfig O=$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) -C $(1) -j16 O=$(3)
	cp $(1)/$(3)/images/trustedcore.img ${PRODUCT_OUT}
	$(call prebuild_teeos_clean, ${TRUSTCORE_HMOS_DIR})

	rm -f $(1)/.config $(1)/.config.old
	rm -f $(1)/ext_apps/hm-apps/tools/linker.lds_pp
	rm -rf $(1)/ext_apps/hm-apps/trustedcore_hm/tools/gcc-plugins/cfi/ifcck_plugin_a32.c
	rm -rf $(1)/ext_apps/hm-apps/trustedcore_hm/tools/gcc-plugins/cfi/ifcck_plugin_cxx_a32.c

	#make -C $(1) release -j16
	#rm -rf $(2)/prebuild/hm-teeos*
	#tar -C $(2)/prebuild -zxf $(1)/hm-teeos-release-v0.1-*.tar.gz
	#mv $(2)/prebuild/hm-teeos-release* $(2)/prebuild/hm-teeos-release
	#chmod +x $(2)/prebuild/hm-teeos-release/tools/ramfsmkimg
	#rm $(1)/hm-teeos-release-*.tar.gz
endef

define prebuilt_hm_teeos_release_es
	mkdir -p $(1)/$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) chip_type=es OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) BUILD_ES_IMG_WITH_CS=$(BUILD_ES_IMG_WITH_CS) -C $(1) clean O=$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) chip_type=es OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) BUILD_ES_IMG_WITH_CS=$(BUILD_ES_IMG_WITH_CS) -C $(1) icos_defconfig O=$(3)
	make TARGET_BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM) chip_type=es OBB_PRODUCT_NAME=$(OBB_PRODUCT_NAME) BUILD_ES_IMG_WITH_CS=$(BUILD_ES_IMG_WITH_CS) -C $(1) -j16 O=$(3)
	cp $(1)/$(3)/images/trustedcore.img ${PRODUCT_OUT}/trustedcore_es.img
	$(call prebuild_teeos_clean, ${TRUSTCORE_HMOS_DIR})
endef

INSTALLED_TRUSTEDCORE_MOD_TARGET := trusted_mod
INSTALLED_TRUSTEDCORE_IMAGE_TARGET := trustedcore.img
INSTALLED_TRUSTEDCORE_ES_IMAGE_TARGET := trustedcore_es.img
TRUSTCORE_HM_DIR = vendor/thirdparty/iTrustee/hm-apps/trustedcore_hm
TRUSTCORE_HMOS_DIR = vendor/thirdparty/iTrustee/hm-teeos
HM_OBJ_DIR := ../../../../$(PRODUCT_OUT)/hm-teeos-build
HAVE_HM := $(shell test -f $(TRUSTCORE_HM_DIR)/Android.mk && echo yes)
ifeq ($(HAVE_HM),yes)

HAVE_HMOS := $(shell test -f $(TRUSTCORE_HMOS_DIR)/Makefile && echo yes)
$(INSTALLED_TRUSTEDCORE_IMAGE_TARGET): 
ifeq (${HAVE_HMOS}, yes)
	$(call prebuilt_hm_teeos_release, ${TRUSTCORE_HMOS_DIR}, ${TRUSTCORE_HM_DIR},${HM_OBJ_DIR})
endif

ifeq ($(BUILD_ES_IMG_WITH_CS), true)
ifeq ($(HAVE_HMOS), yes)
	$(call prebuilt_hm_teeos_release_es, ${TRUSTCORE_HMOS_DIR}, ${TRUSTCORE_HM_DIR},${HM_OBJ_DIR})
endif
endif
else

TRUSTCORE_HM_DIR = vendor/thirdparty/secure_os/trustedcore_hm
$(INSTALLED_TRUSTEDCORE_IMAGE_TARGET): 
	$(call built_trustedcore_image, ${TRUSTCORE_HM_DIR})
ifeq ($(BUILD_ES_IMG_WITH_CS), true)
	$(call built_trustedcore_image_es, ${TRUSTCORE_HM_DIR})
endif
endif

TRUSTCORE_HM_DIR = vendor/huaweiplatform/itrustee/secure_os/trustedcore_hm
$(INSTALLED_TRUSTEDCORE_MOD_TARGET):
	$(call built_trustedcore_mod, ${TRUSTCORE_HM_DIR})
