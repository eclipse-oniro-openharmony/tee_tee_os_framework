set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(triple aarch64-linux-gnu)

get_filename_component(GCC_TOOLCHAIN_ABS_PATH "${CMAKE_CURRENT_LIST_DIR}/../../prebuild/toolchains/gcc-linaro-aarch64-linux-gnu" ABSOLUTE)
set(GCC_C_COMPILER ${GCC_TOOLCHAIN_ABS_PATH}/bin/aarch64-linux-gnu-gcc)

get_filename_component(GUESS_SYSROOT "${CMAKE_CURRENT_LIST_DIR}/../../prebuild/toolchains/gcc-linaro-aarch64-linux-gnu/aarch64-linux-gnu/libc" ABSOLUTE)
set(CMAKE_SYSROOT ${GUESS_SYSROOT})

set(CMAKE_C_COMPILER ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/clang CACHE STRING "Cross C compiler")
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN ${CMAKE_TOOLCHAIN_PATH}/clang+llvm)
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -B${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/ -fuse-ld=lld -nostdlib")

set(CMAKE_ASM_COMPILER ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/clang CACHE STRING "Cross ASM compiler")
set(CMAKE_ASM_LINK_EXECUTABLE ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/ld.lld CACHE STRING "Cross ASM linker")
set(CMAKE_ASM_COMPILER_TARGET ${triple})
set(CMAKE_ASM_LINK_FLAGS "${CMAKE_ASM_LINK_FLAGS} -B${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/ -fuse-ld=lld -nostdlib")

set(CMAKE_CXX_COMPILER ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/clang++ CACHE STRING "Cross CXX compiler")
set(CMAKE_CXX_COMPILER_TARGET ${triple})
set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -B${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/ -fuse-ld=lld -nostdlib")
set(CMAKE_LINKER ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/ld.lld CACHE STRING "Cross linker")

set(CMAKE_DIS ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-dis CACHE STRING "Cross DIS")
set(CMAKE_AS ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-as CACHE STRING "Cross AS")
set(CMAKE_AR ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-ar CACHE STRING "Cross AR")
set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR>  rD <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_RANLIB ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-ranlib CACHE STRING "Cross RANLIB")
set(CMAKE_CXX_ARCHIVE_CREATE ${CMAKE_C_ARCHIVE_CREATE})

set(CMAKE_OBJCOPY ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-objcopy CACHE STRING "Cross OBJCOPY")
set(CMAKE_STRIP ${CMAKE_TOOLCHAIN_PATH}/clang+llvm/bin/llvm-strip CACHE STRING "Cross OBJCOPY")

set(GCC64_TOOLCHAIN_PATH ${CMAKE_TOOLCHAIN_PATH}/gcc-linaro-aarch64-linux-gnu)
set(GCC32_TOOLCHAIN_PATH ${CMAKE_TOOLCHAIN_PATH}/gcc-linaro-arm-linux-gnueabi)

set(CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN ${GCC64_TOOLCHAIN_PATH})
set(CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN ${GCC64_TOOLCHAIN_PATH})
