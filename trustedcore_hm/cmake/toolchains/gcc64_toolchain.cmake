set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

get_filename_component(GUESS_SYSROOT "${CMAKE_CURRENT_LIST_DIR}/../../ext_apps/hm-apps/trustedcore_hm/prebuild/toolchains/clang+llvm" ABSOLUTE)
set(CMAKE_SYSROOT ${GUESS_SYSROOT})

set(CMAKE_C_COMPILER ${CMAKE_TOOLCHAIN_PATH}/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc CACHE STRING "Cross C compiler")
set(CMAKE_CXX_COMPILER ${CMAKE_TOOLCHAIN_PATH}/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-g++ CACHE STRING "Cross CXX compiler")
set(CMAKE_LINKER ${CMAKE_TOOLCHAIN_PATH}/aarch64-linux-gnu-ld CACHE STRING "Cross linker")
