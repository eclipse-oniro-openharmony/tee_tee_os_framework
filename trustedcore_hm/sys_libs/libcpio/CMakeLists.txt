include(rule)
include(flags)
include(common)

set(CPIO_INCLUDES
    ${CPIO_INCLUDES}
    include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/kernel/include/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/kernel/include/arch/arm/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libutils/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libc/include/hm
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libc/musl/arch/generic
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libc/musl/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libc/include/arch/${ARCH}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/libs/syslib/libc/musl/arch/${ARCH}
)

set(CPIO_INCLUDES
    ${CPIO_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../hm-teeos/kernel/include/plat/uapi
)

tee_add_library(cpio STATIC
    SOURCES
    src/cpio.c

    COMPILE_TOOL
    clang

    PRIVATE_INCLUDES
    ${CPIO_INCLUDES}

    COMPILER_FLAGS
    ${COMMON_CFLAGS}

    LINKER_FLAGS
    ${COMMON_LDFLAGS}

    NO_INSTALL
)
