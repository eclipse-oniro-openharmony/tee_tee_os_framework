seplat_external_top_dir := $(abspath ${TOPDIR}/../../../../hisi/hise)
seplat_external_libs_dir := $(abspath ${TOPDIR}/../../../../hisi/bin/hise_libs)
seplat_host_chip_type :=  $(if $(chip_type),$(chip_type),cs)

$(info libseplat_external: TARGET_BOARD_PLATFORM = ${TARGET_BOARD_PLATFORM})
$(info libseplat_external: seplat_host_chip_type = ${seplat_host_chip_type})
$(info libseplat_external: TARGET_BUILD_VARIANT = ${TARGET_BUILD_VARIANT})

define add_seplat_external_library
$(1)_seplat_out_dir := $(abspath $(BUILD_DIR)/platdrv/seplat/libseplat_external/$(1))
$(1)_seplat_source_dir := ${2}
ifeq (${TARGET_BUILD_VARIANT}, user)
$(1)_seplat_libs_dir := ${seplat_external_libs_dir}/${TARGET_BOARD_PLATFORM}_user/teeos/lib
else
$(1)_seplat_libs_dir := ${seplat_external_libs_dir}/${TARGET_BOARD_PLATFORM}/teeos/lib
endif
$(1)_seplat_lib := $$($(1)_seplat_out_dir)/${3}

$$($(1)_seplat_lib):
	$$(NOECHO) mkdir -p $$(dir $$@)
ifneq ($$(wildcard $$($(1)_seplat_source_dir)),)
	$$(NOECHO) echo Exist $${$(1)_seplat_source_dir}
	$$(NOECHO) $(seplat_external_top_dir)/build/scripts/build.sh \
			product=${TARGET_BOARD_PLATFORM} \
			chip_type=${seplat_host_chip_type} \
			output_build=$${$(1)_seplat_out_dir}/build \
			output_install=$${$(1)_seplat_out_dir}/install \
			variant=$(TARGET_BUILD_VARIANT) \
			target=${1};
	$$(NOECHO) cp -rf $${$(1)_seplat_out_dir}/install/teeos/lib/${3} $$@
else
	$$(NOECHO) echo No exist $${$(1)_seplat_source_dir}
	$$(NOECHO) cp -rf $${$(1)_seplat_libs_dir}/${3} $$@
endif

SEPLAT_EXTERNAL_LIBS += $$($(1)_seplat_lib)
endef

$(eval $(call add_seplat_external_library,seplat_data_link_teeos,${seplat_external_top_dir}/common/data_link,libseplat_data_link.a))

$(word 1, $(CFILES)): $(SEPLAT_EXTERNAL_LIBS)
