include(apps_svc_common)
file(GLOB HWSECUREC_HOST_SRCS src/*.c)

string(FIND ${PROJECT_SOURCE_DIR} "hm-teeos" IS_TEEOS)
if (IS_TEEOS GREATER 0)
    list(APPEND HOST_C_FLAGS
        -include${HMSDKINCLUDE}/autoconf.h
    )
else()
    list(APPEND HOST_C_FLAGS
        -include${PREBUILD_DIR}/headers/autoconf.h
    )
endif()

tee_add_library(hwsecurec_host STATIC
    SOURCES
    ${HWSECUREC_HOST_SRCS}

    COMPILE_TOOL
    host

    PRIVATE_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../libhwsecurec/include/libhwsecurec
    ${CMAKE_CURRENT_SOURCE_DIR}/../libhwsecurec/include

    COMPILER_FLAGS
    -Wall
    -Wextra
    -Werror
    -fstack-protector-all
    -Os
    ${HOST_C_FLAGS}
    -nodefaultlibs
    -fno-omit-frame-pointer
    -fno-short-enums
    -fno-builtin

    COMPILER_DEFINITIONS
    -DARCH_ARM -DAARCH64
    -D__KERNEL_64__
    -DARMV8_A
    -DARM_CORTEX_A53
    -DKIRIN
    -DSECUREC_MEMSET_INDIRECT_USE=0
    -DHAVE_AUTOCONF
    -DVFMW_EXTRA_TYPE_DEFINE
    -DENV_SOS_KERNEL

    LINKER_FLAGS
    -lgcc

    LIBS_INSTALL_PATH
    lib

    NO_INSTALL
)
