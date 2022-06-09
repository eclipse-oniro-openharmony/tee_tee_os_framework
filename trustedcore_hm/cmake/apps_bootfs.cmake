if ("${PERF_FUATURE}" STREQUAL "true")
    list(APPEND BOOTFS_FILES
        ${PREBUILD_APPS}/perf
    )
endif()

if ("${BENCHMARK}" STREQUAL "true")
    list(APPEND BOOTFS_FILES
        ${PREBUILD_APPS}/benchmark_a32
    )
endif()

if (NOT "${CONFIG_SMCMGR_EMBEDDED}" STREQUAL "y")
    list(APPEND BOOTFS_FILES_IN_PREBUILD "teesmcmgr.elf")
endif()

if ("${CONFIG_DYNLINK_TEST}" STREQUAL "y")
    list(APPEND BOOTFS_FILES
        ${PREBUILD_LIBS}/arm/libtest_shared_a32.so
    )
endif()

if ("${CONFIG_TA_64BIT}" STREQUAL "true")
    list(APPEND BOOTFS_FILES_IN_PREBUILD libc_shared.so)
endif()
if ("${CONFIG_TA_32BIT}" STREQUAL "true")
    list(APPEND BOOTFS_FILES_IN_PREBUILD libc_shared_a32.so)
endif()

if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true")
    list(APPEND BOOTFS_FILES ${BOOTFS_STAGE_DIR}/libdrv_shared.so)
endif()

if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "false" OR "${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "false" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND BOOTFS_FILES ${BOOTFS_STAGE_DIR}/libdrv_shared_a32.so)
endif()

file(GLOB BOOTFS_STAGE_FILES LIST_DIRECTORIES false ${BOOTFS_STAGE_DIR}/*)
foreach (f ${BOOTFS_STAGE_FILES})
    list(APPEND BOOTFS_FILES ${f})
endforeach()

if ("${BUILD_TOOL}" STREQUAL "clang")
add_custom_target(bootfs
    COMMAND STRIP=${CMAKE_STRIP} ${PROJECT_SOURCE_DIR}/tools/smart-strip.sh ${BOOTFS_FILES}
    COMMAND ${HOST_BINS_DIR}/ramfsmkimg -n ${HM_BOOTFS_SIZE} -f ${PROJECT_SOURCE_DIR}/tools/bootfs.ini bootfs.img ${BOOTFS_FILES}
    VERBATIM)
endif()
