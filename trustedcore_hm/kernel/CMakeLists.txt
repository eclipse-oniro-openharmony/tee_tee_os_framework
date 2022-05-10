include(flags)
include(common)
include(subCommon)
include(apps_var_and_config)
include(kernel)
include(apps_plat)
include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/product_config.cmake)

set(KERNEL_INCLUDE_DIRS
    libgic
    libversion
    elfloader/include
    ../platform/common/include
    libuart
    libuart/pl011
    libuart/pl011_general
    libuart/pl011_v500
    libuart/uart_lpc
    ${PREBUILD_HEADER}/kernel/capability
    ${PREBUILD_HEADER}/kernel/include
    ${PREBUILD_HEADER}/kernel/include/uapi
    ${PREBUILD_HEADER}/kernel/include/stdlib
    ${PREBUILD_HEADER}/kernel/include/plat/uapi
    ${PREBUILD_HEADER}/kernel/include/plat
    ${PREBUILD_HEADER}/kernel/include/arch/arm
    ${PREBUILD_HEADER}
)

set(DEFS
    ${DEFS}
    HMAPPS_COMMIT_ID="${HMAPPS_COMMIT}"
)

MESSAGE( STATUS "HMAPPS_COMMIT_ID = ${HMAPPS_COMMIT_ID}.")

if ("${ARCH}" STREQUAL "aarch64")
    set(KERNEL_INCLUDE_DIRS
        ${KERNEL_INCLUDE_DIRS}
        ${PREBUILD_HEADER}/kernel/include/plat/plat/64
        ${PREBUILD_HEADER}/kernel/include/arch/arm/arch/64
    )
else()
    set(KERNEL_INCLUDE_DIRS
        ${KERNEL_INCLUDE_DIRS}
        ${PREBUILD_HEADER}/kernel/include/plat/plat/32
        ${PREBUILD_HEADER}/kernel/include/arch/arm/arch/32
    )
endif()

if ("${BUILD_KERNEL}" STREQUAL "y")
preprocess_files(preprocess_asm_files
    SOURCES
    ${KERNEL_SRCS}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
    ${GENERAL_OPTIONS}

    COMPILER_DEFINITIONS
    ${KERNEL_COMPILER_DEFINITIONS}
    ${DEFS}

    PRIVATE_INCLUDES
    ${KERNEL_INCLUDE_DIRS}
)

###############
# libuart #
###############
set(LIBUART_SRCS
    libuart/io_output.c
    libuart/uart_register.c
    libuart/pl011/pl011.c
    libuart/pl011_general/pl011_general.c
    libuart/pl011_v500/pl011_v500.c
    libuart/uart_lpc/uart_lpc.c
)

tee_add_library(uart STATIC
    SOURCES
    ${LIBUART_SRCS}

    COMPILE_TOOL
    clang

    PRIVATE_INCLUDES
    ${KERNEL_INCLUDE_DIRS}

    COMPILER_DEFINITIONS
    ${KERNEL_COMPILER_DEFINITIONS}
    ${DEFS}

    COMPILER_FLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
    ${CFLAGS}
    ${KERNEL_CFLAGS}
    ${GENERAL_OPTIONS}
    ${KERNEL_SPECIAL_CFLAGS}
)

###############
# libgic #
###############
set(LIBGIC_SRCS
    libgic/gic_v2.c
    libgic/gic_v3.c
)

tee_add_library(gic STATIC
    SOURCES
    ${LIBGIC_SRCS}

    COMPILE_TOOL
    clang

    PRIVATE_INCLUDES
    ${KERNEL_INCLUDE_DIRS}

    COMPILER_DEFINITIONS
    ${KERNEL_COMPILER_DEFINITIONS}
    ${DEFS}

    COMPILER_FLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
    ${CFLAGS}
    ${KERNEL_CFLAGS}
    ${GENERAL_OPTIONS}
    ${KERNEL_SPECIAL_CFLAGS}
)

###############
# libversion #
###############
set(LIBVERSION_SRCS
    libversion/tee_version.c
)

tee_add_library(version STATIC
    SOURCES
    ${LIBVERSION_SRCS}

    COMPILE_TOOL
    clang

    PRIVATE_INCLUDES
    ${KERNEL_INCLUDE_DIRS}

    COMPILER_DEFINITIONS
    ${KERNEL_COMPILER_DEFINITIONS}
    ${DEFS}

    COMPILER_FLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
    ${CFLAGS}
    ${KERNEL_CFLAGS}
    ${GENERAL_OPTIONS}
    ${KERNEL_SPECIAL_CFLAGS}
)

set(LDS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/linker.lds)

preprocess_lds(preprocess_lds_file
    LDS_FILE
    ${LDS_FILE}

    COMPILE_TOOL
    clang

    COMPILER_DEFINITIONS
    ${KERNEL_COMPILER_DEFINITIONS}
    ${DEFS}

    PRIVATE_INCLUDES
    ${KERNEL_INCLUDE_DIRS}

    COMPILE_FLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
)

if ("${ARCH}" STREQUAL "aarch64")
    set(GCC_TOOLCHAIN_PATH ${GCC64_TOOLCHAIN_PATH})
else()
    set(GCC_TOOLCHAIN_PATH ${GCC32_TOOLCHAIN_PATH})
endif()

set_property(SOURCE ${CMAKE_CURRENT_BINARY_DIR}/linker.lds PROPERTY GENERATED TRUE)

if ("${ARCH}" STREQUAL "aarch64")
    set(GCC_LINKER ${GCC64_TOOLCHAIN_PATH}/bin/aarch64-linux-gnu-ld)
else()
    set(GCC_LINKER ${GCC32_TOOLCHAIN_PATH}/bin/arm-linux-gnueabi-ld)
endif()

set(KERNEL_LIBRARIES
    uart
    gic
    version
)

set(KERNEL_TEEOS_LIBRARIES
    hardware
    kernel
    verified
    sched
    kipc
    kcmd
    futex
    cap
    klibc
    smp
    traps
)

set(KERNEL_TARGET_LIBRARIES)
foreach(l ${KERNEL_LIBRARIES})
    list(APPEND KERNEL_TARGET_LIBRARIES $<TARGET_FILE:${l}>)
endforeach()

set(KERNEL_PREBUILD_LIBRARIES)
foreach(l ${KERNEL_TEEOS_LIBRARIES})
    list(APPEND KERNEL_PREBUILD_LIBRARIES -l${l})
endforeach()

add_custom_target(kernel.elf)
add_custom_command(TARGET kernel.elf
    COMMAND ${GCC_LINKER} ${KERNEL_LDFLAGS} -T${CMAKE_CURRENT_BINARY_DIR}/linker.lds -L${PREBUILD_KERNEL_LIBS} -o ${CMAKE_CURRENT_BINARY_DIR}/kernel.elf --start-group ${KERNEL_TARGET_LIBRARIES} ${KERNEL_PREBUILD_LIBRARIES} --end-group
    COMMAND_EXPAND_LISTS
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/kernel.elf ${BOOTFS_OUT}
)
if ("${BUILD_TOOL}" STREQUAL "clang")
    add_dependencies(kernel.elf preprocess_lds_file uart gic version)
endif()

endif()

#############
# elfloader #
#############
set(ELFLOADER_C_SRCS
    ${ELFLOADER_C_SRCS}
    elfloader/src/arch-arm/data.c
    elfloader/src/arch-arm/random.c
    elfloader/src/arch-arm/uncompr.c
    elfloader/src/arch-arm/smp_boot.c
    elfloader/src/arch-arm/elfloader_main.c
    elfloader/src/arch-arm/snapshot.c
    elfloader/src/usr_put_char.c
)
set(ELFLOADER_C_SRCS
    ${ELFLOADER_C_SRCS}
    elfloader/src/smp.c
)
if ("${ARCH}" STREQUAL "aarch64")
    set(ELFLOADER_C_SRCS
        ${ELFLOADER_C_SRCS}
        elfloader/src/arch-arm/64/mmu.c
        elfloader/src/arch-arm/64/psci.c
        elfloader/src/arch-arm/64/timer.c
    )
    set(ELFLOADER_ASM_SRCS
        ${ELFLOADER_ASM_SRCS}
        elfloader/src/arch-arm/64/crt0.S
        elfloader/src/arch-arm/64/traps.S
        elfloader/src/arch-arm/64/psci_asm.S
        elfloader/src/arch-arm/64/cache_flush.S
    )
else()
    set(ELFLOADER_C_SRCS
        ${ELFLOADER_C_SRCS}
        elfloader/src/arch-arm/32/mmu.c
        elfloader/src/arch-arm/32/psci.c
        elfloader/src/arch-arm/32/timer.c
    )
    set(ELFLOADER_ASM_SRCS
        ${ELFLOADER_ASM_SRCS}
        elfloader/src/arch-arm/32/crt0.S
        elfloader/src/arch-arm/32/traps.S
        elfloader/src/arch-arm/32/psci_asm.S
    )
endif()

if ("${__EFI__}" STREQUAL "y")
    set(ELFLOADER_ASM_SRCS
        ${ELFLOADER_ASM_SRCS}
        elfloader/src/binaries/efi/efi_head.S
    )
    set(ENTRY_POINT efi_stub_entry)
endif()

if ("${ARCH}" STREQUAL "aarch64")
    set(ELFLOADER_LIBRARIES
            cpio
            zlib_64
    )
else()
    set(ELFLOADER_LIBRARIES
            cpio_a32
            zlib_a32
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
set(ELFLOADER_INCLUDES
    ${ELFLOADER_INCLUDES}
    ${PREBUILD_HEADER}/kernel/include/arch/arm/arch/64
    ${PREBUILD_HEADER}/kernel/include/plat/plat/64
    ${PREBUILD_HEADER}/libc/arch/aarch64
)
else()
set(ELFLOADER_INCLUDES
    ${ELFLOADER_INCLUDES}
    ${PREBUILD_HEADER}/kernel/include/arch/arm/arch/32
    ${PREBUILD_HEADER}/kernel/include/plat/plat/32
    ${PREBUILD_HEADER}/libc_32/arch/arm
)
endif()

set(ELFLOADER_INCLUDES
    ${ELFLOADER_INCLUDES}
    ${PROJECT_SOURCE_DIR}/platform/common/include
    ${PROJECT_SOURCE_DIR}/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/plat_cfg
    ${PREBUILD_DIR}/headers/zlib
    ${PROJECT_SOURCE_DIR}/kernel/libuart
    ${CMAKE_CURRENT_SOURCE_DIR}/elfloader/include/arch-arm/${ARCH_TYPE}
    ${CMAKE_CURRENT_SOURCE_DIR}/elfloader/include/arch-arm
    ${CMAKE_CURRENT_SOURCE_DIR}/elfloader/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/arch/arm
    ${CMAKE_CURRENT_SOURCE_DIR}/include/arch/arm/arch/${ARCH_TYPE}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/plat
    ${CMAKE_CURRENT_SOURCE_DIR}/include/plat/plat/${ARCH_TYPE}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/include/stdlib
    ${CMAKE_CURRENT_SOURCE_DIR}/include/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/include/plat/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/klibc/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../sys_libs/libcpio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../sys_libs/libelf/include
    ${PREBUILD_HEADER}
    ${PREBUILD_HEADER}/sys
    ${PREBUILD_HEADER}/ddk/hmapi
    ${PREBUILD_HEADER}/kernel/capability
    ${PREBUILD_HEADER}/kernel/include
    ${PREBUILD_HEADER}/ddk/hmapi
    ${PREBUILD_HEADER}/kernel/include/machine
    ${PREBUILD_HEADER}/kernel/include/lib
    ${PREBUILD_HEADER}/kernel/include/uapi
    ${PREBUILD_HEADER}/kernel/include/stdlib
    ${PREBUILD_HEADER}/kernel/include/plat/uapi
    ${PREBUILD_HEADER}/kernel/include/plat
    ${PREBUILD_HEADER}/kernel/include/arch/arm
    ${PREBUILD_LIBC_INC}
    ${PREBUILD_LIBC_INC}/arch/generic
    ${HDR_L_DIR}
    ${PREBUILD_HEADER}/kernel/klibc
)

set(ELFLOADER_CFLAGS
    -include${PREBUILD_DIR}/headers/autoconf.h
    ${CFLAGS}
    ${COMMON_CFLAGS}
    ${KERNEL_SPECIAL_CFLAGS}
    -D_XOPEN_SOURCE=700
    -ffreestanding
    -Wall
    -Wextra
    -Werror
    -W
    -D__IN_KERNEL__
    -fpie
)

if ("${CONFIG_BOOT_ARGS_TRANSFER}" STREQUAL "true")
set(ELFLOADER_CFLAGS
    ${ELFLOADER_CFLAGS}
    -DBOOT_ARGS_TRANSFER
)
endif()

if ("${CONFIG_NO_PLATCFG_EMBEDDED}" STREQUAL "true")
set(ELFLOADER_CFLAGS
    ${ELFLOADER_CFLAGS}
    -DNO_PLATCFG_EMBEDDED
    -DBOOT_ARGS_TRANSFER
)
endif()

set(LD_FLAGS
    ${LD_FLAGS}
    -Wl,-r
    -Wl,-static
    -Wl,-z,relro
    -Wl,-z,now
)

if ("${ARCH}" STREQUAL "aarch64")
set(LD_FLAGS
    ${LD_FLAGS}
    -L${PREBUILD_LIBS}/aarch64
)
else()
set(LD_FLAGS
    ${LD_FLAGS}
    -L${PREBUILD_LIBS}/arm
)
endif()

list(REMOVE_ITEM ELFLOADER_CFLAGS "-ffunction-sections")
list(REMOVE_ITEM ELFLOADER_CFLAGS "-fdata-sections")

if ("${BUILD_KERNEL}" STREQUAL "y")
tee_add_executable(elfloader.o
    C_SOURCES
    ${ELFLOADER_C_SRCS}

    ASM_SOURCES
    ${ELFLOADER_ASM_SRCS}

    COMPILE_TOOL
    clang

    C_PRIVATE_INCLUDES
    ${ELFLOADER_INCLUDES}
    ${COMMON_INCLUDES}
    ${COMMON_NWEFLAG_INCLUDES}
    ${BOOTSTRAP_INCLUDES}

    ASM_PRIVATE_INCLUDES
    ${ELFLOADER_INCLUDES}
    ${COMMON_INCLUDES}
    ${COMMON_NWEFLAG_INCLUDES}
    ${BOOTSTRAP_INCLUDES}

    C_COMPILER_FLAGS
    ${ELFLOADER_CFLAGS}

    ASM_COMPILER_FLAGS
    ${ELFLOADER_CFLAGS}

    C_COMPILER_DEFINITIONS
    ${DEFS}

    ASM_COMPILER_DEFINITIONS
    ${DEFS}

    LD_FLAGS
    ${LD_FLAGS}
    ${RUNTIMELIB_LINK_PATH}

    LINKGROUP
    ${ELFLOADER_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    bin

    NO_CFI
)

if ("${BUILD_TOOL}" STREQUAL "clang")
    SET_TARGET_PROPERTIES(elfloader.o PROPERTIES PREFIX "")
    SET_TARGET_PROPERTIES(elfloader.o PROPERTIES SUFFIX "")
endif()
endif()
