set(HDR_L_DIR ${OUTPUTDIR}/headers)
set(LIB_DIR ${OUTPUTDIR}/${ARCH}/libs/)

if ("${BUILD_KERNEL}" STREQUAL "y")
    set(KERNEL_OUTDIR ${OUTPUTDIR}/kernel)
endif()

set(PREBUILD_DIR ${PREBUILD_PATH}/hm-teeos-local-release)
set(PREBUILD_HEADER ${PREBUILD_DIR}/headers)
set(PREBUILD_LIBS ${PREBUILD_DIR}/libs)
set(PREBUILD_TOOLS ${PREBUILD_DIR}/tools)
set(PREBUILD_APPS ${PREBUILD_DIR}/apps)
set(PREBUILD_SDK "${PREBUILD_DIR}/headers/sdk")
set(PREBUILD_INNER_SDK "${PREBUILD_DIR}/headers/inner_sdk")
set(PREBUILD_DDK "${PREBUILD_DIR}/headers/ddk")
set(PREBUILD_SYS  "${PREBUILD_DIR}/headers/sys")
set(PREBUILD_KERNEL "${PREBUILD_DIR}/headers/kernel")
set(PREBUILD_KERNEL_LIBS "${PREBUILD_DIR}/kernel/${ARCH}")

if ("${ARCH}" STREQUAL "arm")
    set(PREBUILD_LIBC_INC ${PREBUILD_HEADER}/libc_32)
else()
    set(PREBUILD_LIBC_INC ${PREBUILD_HEADER}/libc)
endif()

set(PREBUILD_ARCH_PLAT_LIBS "${PREBUILD_LIBS}/${ARCH}")

if ("${QUICK_BOOT_CHK}" STREQUAL "true")
    set(WITH_TEEOS_ENCRYPT false)
else()
    set(WITH_TEEOS_ENCRYPT true)
endif()

if ("${TARGET_BUILD_VARIANT}" STREQUAL "y")
    set(WITH_ENG_VERSION y)
else()
    set(WITH_ENG_VERSION n)
endif()

if ("${WITH_ENG_VERSION}" STREQUAL "y")
    set(TRUSTEDCORE_PLATFORM_FLAGS
        ${TRUSTEDCORE_PLATFORM_FLAGS}
        -DDEF_ENG
        -DSECMEM_UT
    )
else()
    set(TRUSTEDCORE_PLATFORM_FLAGS
        ${TRUSTEDCORE_PLATFORM_FLAGS}
        -DDEF_ENG
    )
endif()

if ("${RELEASE_SIGN}" STREQUAL "true")
    set(TRUSTEDCORE_PLATFORM_FLAGS
        ${TRUSTEDCORE_PLATFORM_FLAGS}
        -DRELEASE_SIGN_BUILD_TEE
    )
endif()

if (EXISTS ${PREBUILD_DIR})
    set(HM_SDK_VER hm-teeos-local-release)
else()
    set(HM_SDK_VER hm-teeos-release)
endif()

set(HM_BOOTFS_SIZE 8000K)
