cmake_minimum_required(VERSION 3.14.1 FATAL_ERROR)

project(apps C CXX ASM)

SET_PROPERTY(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

message("[${VERSION}][INFO] This project is built using CMake")

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "[${VERSION}][ERROR] Forbid compiling in the source tree")
endif()

include(TeeCommon)
include(parse_config_file)
parse_config_file(${CONFIG_FILE})

set(CHOOSE_LLD
    -B${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/
    -fuse-ld=lld
)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -Werror
)

set(RPODUCT_APPS)
set(HM_PLATFORM kirin)
include(apps_var_and_config)

set(PLATFORM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/platform)
include(apps_plat)
set(PLAT_CFG_DIR ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg)
set(PLAT_COMMON_DIR ${PLATFORM_DIR}/common)

list(APPEND CMAKE_MODULE_PATH ${PLATFORM_DIR}/${PLATFORM_NAME})
include(platform)
include(apps_cfg)
include(project)

set(XOM_LIB_LDS ${PROJECT_SOURCE_DIR}/cmake/linker.lib.xom.ld)
set(XOM_LDS ${PROJECT_SOURCE_DIR}/cmake/linker.xom.ld)

if ("${ARCH}" STREQUAL "aarch64")
    set(PRODUCT_APPS ${PRODUCT_APPS_64})
endif()
if ("${ARCH}" STREQUAL "arm")
    set(PRODUCT_APPS ${PRODUCT_APPS_32})
endif()

#######################
# thumb codes support #
#######################
if ("${ARCH}" STREQUAL "arm")
    list(REMOVE_ITEM TEE_C_FLAGS "-march=armv8-a")
    if ("${CONFIG_THUMB_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -mthumb
        )
    endif()

    if ("${CONFIG_ARM_CORTEX_A15}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -march=armv7ve
        )
    endif()

    if ("${CONFIG_ARM_CORTEX_A53}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -march=armv8-a
        )
    endif()
else()
    list(APPEND TEE_C_FLAGS
        -march=armv8-a
    )
endif()

add_subdirectory(kernel)
add_subdirectory(sys_libs)
add_subdirectory(sys_apps)
add_subdirectory(libs)
add_subdirectory(apps)
add_subdirectory(thirdparty)
add_subdirectory(framework)
add_subdirectory(thirdparty/vendor/libdxcc)
add_subdirectory(tools/hmfilemgr)
add_subdirectory(tools/img_encry_kunpeng)
add_subdirectory(tools/scramb_syms_host)
add_subdirectory(tools/xom)
add_subdirectory(tools/cpio-strip)
add_subdirectory(vendor/${PLATFORM_NAME})
add_subdirectory(drivers/drv_timer)
add_subdirectory(drivers/tee_drv_server)
add_subdirectory(drivers/base_mgr/tee_misc_driver)
if ("${CRYPTO_MGR_SERVER_ENABLE}" STREQUAL "true")
add_subdirectory(drivers/base_mgr/crypto_mgr)
endif()

if ("${BUILD_TEST}" STREQUAL "y")
    add_subdirectory(tee-tests)
endif()

add_custom_target(plat_cfg_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h ${HDR_L_DIR}
    VERBATIM)

add_custom_target(install_headers_64)
add_custom_target(install_headers_32)
add_dependencies(install_headers_64 libart_headers libbiometric_headers libchinadrm_headers libteeconfig_headers libtimer_headers librot_headers libvltmm_headers libweaver_headers libswcrypto_engine_headers libdrv_frame_headers libhmdrv_stub_headers libteeagentcommon_client_headers libcrypto_hal_headers libbz_hm_headers plat_cfg_headers)
add_dependencies(install_headers_32 libart_a32_headers libbiometric_a32_headers libchinadrm_a32_headers libteeconfig_headers libtimer_headers librot_headers libvltmm_a32_headers libweaver_a32_headers libswcrypto_engine_headers libdrv_frame_headers libhmdrv_stub_headers libteeagentcommon_client_headers libcrypto_hal_headers libbz_hm_headers plat_cfg_headers)

if ("${CONFIG_CRYPTO_ENGINE_DX}" STREQUAL "y")
    add_dependencies(install_headers_32 libdxcc_headers)
    add_dependencies(install_headers_64 libdxcc_headers)
endif()

if ("${CHIP_NAME}" STREQUAL "shaolingun")
    add_dependencies(install_headers_32 libdevchip_api_headers)
    add_dependencies(install_headers_64 libdevchip_api_headers)
endif()

include(apps_bootfs)

if ("${BUILD_TOOL}" STREQUAL "host")
    add_custom_target(release_host)
    add_dependencies(release_host ${PRODUCT_RELEASE_HOST})
    add_dependencies(release_host cpio-strip)
endif()
if ("${BUILD_TOOL}" STREQUAL "clang")
    foreach(r ${PRODUCT_APPS_64})
        list(FIND PRODUCT_RELEASE_64 ${r} index)
        if (${index} LESS 0)
            list(APPEND PRODUCT_RELEASE_APPEND_64 ${r})
        endif()
    endforeach()
    list(APPEND PRODUCT_RELEASE_64 ${PRODUCT_RELEASE_APPEND_64})

    foreach(r ${PRODUCT_APPS_32})
        list(FIND PRODUCT_RELEASE_32 ${r} index)
        if (${index} LESS 0)
            list(APPEND PRODUCT_RELEASE_APPEND_32 ${r})
        endif()
    endforeach()
    list(APPEND PRODUCT_RELEASE_32 ${PRODUCT_RELEASE_APPEND_32})

    add_custom_target(release_64)
    add_custom_target(release_32)
    add_dependencies(release_64 ${PRODUCT_RELEASE_64} ${KERNEL_RELEASE_64})
    add_dependencies(release_32 ${PRODUCT_RELEASE_32} ${KERNEL_RELEASE_32})
endif()

add_custom_target(prepare_bins)
add_custom_target(prepare_kernel)
add_custom_command(TARGET prepare_kernel
    COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUTDIR}/kernel/elfloader.o ${BOOTFS_OUT}/elfloader.o
)

if ("teesmcmgr.elf" IN_LIST BOOTFS_FILES_IN_PREBUILD)
    add_custom_command(TARGET prepare_bins
        COMMAND ${CMAKE_COMMAND} -E copy ${PREBUILD_APPS}/teesmcmgr.elf ${BOOTFS_STAGE_DIR}/teesmcmgr.elf
    )
endif()
if ("libc_shared.so" IN_LIST BOOTFS_FILES_IN_PREBUILD)
    add_custom_command(TARGET prepare_bins
        COMMAND ${CMAKE_COMMAND} -E copy ${PREBUILD_LIBS}/aarch64/libc_shared.so ${BOOTFS_STAGE_DIR}/libc_shared.so
    )
endif()
if ("libc_shared_a32.so" IN_LIST BOOTFS_FILES_IN_PREBUILD)
    add_custom_command(TARGET prepare_bins
        COMMAND ${CMAKE_COMMAND} -E copy ${PREBUILD_LIBS}/arm/libc_shared_a32.so ${BOOTFS_STAGE_DIR}/libc_shared_a32.so
    )
endif()

#################
# check symbols #
#################
if ("${BUILD_TOOL}" STREQUAL "clang")
    add_custom_target(check_symbols)
    if ("${ARCH}" STREQUAL "aarch64")
        set(CANDIDATE_BINS ${PRODUCT_RELEASE_64})
        set(C_SHARED_SO ${PREBUILD_LIBS}/aarch64/libc_shared.so)
        set(DRV_SHARED_SO ${OUTPUTDIR}/sys_libs/libdrv_shared/libdrv_shared.so)
    else()
        set(CANDIDATE_BINS ${PRODUCT_RELEASE_32})
        set(C_SHARED_SO ${PREBUILD_LIBS}/arm/libc_shared_a32.so)
        set(DRV_SHARED_SO ${OUTPUTDIR}/sys_libs/libdrv_shared_a32/libdrv_shared_a32.so)
    endif()
    set(TEE_SHARED_SO $<TARGET_FILE:tee_shared>)
    set(VENDOR_SHARED_SO $<TARGET_FILE:vendor_shared>)
    set(BASE_SHARED_SO $<TARGET_FILE:base_shared>)

    foreach (b ${CANDIDATE_BINS})
        if (${b} MATCHES ".elf")
            add_custom_command(TARGET check_symbols
                COMMAND ${PROJECT_SOURCE_DIR}/tools/check-syms.sh $<TARGET_FILE:${b}> ${C_SHARED_SO} ${TEE_SHARED_SO} ${VENDOR_SHARED_SO} ${DRV_SHARED_SO} ${BASE_SHARED_SO}
            )
        endif()
    endforeach()
endif()

####################
# scramble symbols #
####################
set(SCRAMBLE_BIN ${HOST_BINS_DIR}/scramb_syms_host)
add_custom_target(scramble_bootfs_symbols)
add_custom_target(scramble_hmfilemgr_symbols)
add_custom_target(scramble_hmsysmgr_symbols)

set(SCRAMBLED_KERNEL_DIR ${BOOTFS_OUT})

#######
# XOM #
#######
set(XOM_BIN ${HOST_BINS_DIR}/xom)
add_custom_target(use_xom32)
add_custom_target(remove_xomloc_section)
add_custom_target(use_xom32_hmfilemgr)
add_custom_target(use_xom32_hmsysmgr)
add_custom_target(remove_xomloc_section_hmfilemgr)
add_custom_target(remove_xomloc_section_hmsysmgr)
set(XOM_FINISH_FILE)

############
# pack img #
############
include(apps_svc_flags)
foreach (i ${TEE_C_FLAGS})
        set(SDK_CPPFLAGS
            ${SDK_CPPFLAGS}
            ${i}
        )
endforeach()

set(SDK_CPPFLAGS
    ${SDK_CPPFLAGS}
    -I${PREBUILD_DIR}/headers
    -I${PREBUILD_DIR}/headers/ddk/legacy
    -I${PREBUILD_DIR}/headers/sys/hmapi
    -I${PREBUILD_DIR}/headers/sys/hmapi/kernel
    -I${PREBUILD_DIR}/headers/sys/legacy
    -I${PREBUILD_DIR}/headers/ddk/hmapi
    --gcc-toolchain=${GCC_TOOLCHAIN_PATH}
    --sysroot=${CMAKE_SYSROOT}
    --target=${CMAKE_C_COMPILER_TARGET}
)
list(REMOVE_ITEM SDK_CPPFLAGS "-fsanitize=cfi")
list(REMOVE_ITEM SDK_CPPFLAGS "-flto")

set(WITH_LOG_ENCODE false)
set(COMPARE_IMAGE 0)

set(IMAGE_NAME teehm.img.elf)
set(BOOT_APPS ${PROJECT_BINARY_DIR}/tools/hmfilemgr/hmfilemgr ${PROJECT_BINARY_DIR}/framework/hmsysmgr/hmsysmgr)

set(DDK_FLAG false)
add_custom_target(gen_trustedcore_image
    COMMAND ${CMAKE_COMMAND} -E copy ${PREBUILD_KERNEL_LIBS}/libklibc.a ${KERNEL_OUTDIR}/
    COMMAND ${CMAKE_COMMAND} -E copy ${PREBUILD_KERNEL_LIBS}/libhardware.a ${KERNEL_OUTDIR}/
    COMMAND cd ${PROJECT_SOURCE_DIR}&&SDK_CPPFLAGS='${SDK_CPPFLAGS}' DDK_FLAGS=${DDK_FLAG} PREBUILD_DIR=${PREBUILD_DIR} ELFLOADER_DIR=${KERNEL_OUTDIR} KERNEL_OUTDIR=${KERNEL_OUTDIR} OUTPUTDIR=${PROJECT_BINARY_DIR} STRIP=${CMAKE_STRIP} TOPDIR=${PROJECT_SOURCE_DIR} LD=${CMAKE_LINKER} CC=${CMAKE_C_COMPILER} PLAT_COMMON_DIR=${PLAT_COMMON_DIR} PLAT_CFG_DIR=${PLAT_CFG_DIR} PLATFORM_DIR=${PLATFORM_DIR} TARGET_BOARD_PLATFORM=${TARGET_BOARD_PLATFORM} GCC_LD_A32=${PROJECT_SOURCE_DIR}/prebuild/toolchains/gcc-linaro-arm-linux-gnueabi/bin/arm-linux-gnueabi-ld GCC_LD_A64=${PROJECT_SOURCE_DIR}/prebuild/toolchains/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-ld TOOLCHAIN_ROOT=${PROJECT_SOURCE_DIR}/prebuild/toolchains HM_ARCH=${ARCH} CONFIG_NO_ZIP_IMAGE=${CONFIG_NO_ZIP_IMAGE} TEE_ARCH=${ARCH} HM_SDK_VER=${HM_SDK_VER} ${PROJECT_SOURCE_DIR}/tools/gen_boot_image.sh ${SCRAMBLED_KERNEL_DIR}/kernel.elf ${BOOT_APPS} ${IMAGE_ROOT}/${IMAGE_NAME} 2>&1
    COMMAND ${CMAKE_OBJCOPY} -O binary ${IMAGE_ROOT}/${IMAGE_NAME} ${IMAGE_ROOT}/teehm.img
    COMMAND HM_ARCH=${ARCH}  CONFIG_NO_ZIP_IMAGE=${CONFIG_NO_ZIP_IMAGE} IMAGE_ROOT=${IMAGE_ROOT} ${PROJECT_SOURCE_DIR}/tools/packimg.sh ${TRUSTEDCORE_PHY_TEXT_BASE} ${TRUSTEDCORE_PLATFORM_CHOOSE} ${COMPARE_IMAGE} ${TRUSTEDCORE_CHIP_CHOOSE} ${WITH_TEEOS_ENCRYPT} ${WITH_LOG_ENCODE} ${TRUSTEDCORE_PHY_IMAGE_LOAD_BASE})

####################
# test output      #
####################
if ("${BUILD_TEST}" STREQUAL "y")
add_custom_target(cp_test_ta_64)
add_custom_target(cp_test_ta_32)

if ("${ARCH}" STREQUAL "aarch64")
    foreach(r ${TEST_APPS_DIR_64})
        if (EXISTS ${OUTPUTDIR}/tee-tests/tests64/${r})
            add_custom_command(TARGET cp_test_ta_64
                COMMAND ${CMAKE_COMMAND} -E copy_directory ${OUTPUTDIR}/tee-tests/tests64/${r}/  ${CMAKE_CURRENT_SOURCE_DIR}/../../hm-teeos/build/arm/${r}/
            )
        endif()
    endforeach()
else()
    foreach(r ${TEST_APPS_DIR_32})
        if (EXISTS ${OUTPUTDIR}/tee-tests/tests32/${r})
            add_custom_command(TARGET cp_test_ta_32
                COMMAND ${CMAKE_COMMAND} -E copy_directory ${OUTPUTDIR}/tee-tests/tests32/${r}/  ${CMAKE_CURRENT_SOURCE_DIR}/../../hm-teeos/build/arm/${r}/
            )
        endif()
    endforeach()
endif()

endif()
