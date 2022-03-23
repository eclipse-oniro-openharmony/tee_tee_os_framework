1. Input command "make", compile output $(TA_UUID).bin, $(TA_UUID).elf
   1) Default output directory $(CURDIR)/out
   2) $(TA_UUID).bin For trustedcore, along with context of manifest.txt, signed with a signature tool to become Dynamic TA.
   3) $(TA_UUID).elf For trustedcore.

2. Input command "make clean", delete the compiled file.

3. manifest.txt: Attribute description file for Trustedcore Dynamic TA.
   gpd.ta.appID              ---- TA's UUID
   gpd.ta.service_name       ---- TA's name. Eg: dynamic_load_demo
   gpd.ta.singleInstance     ---- TA whether is a single instance. Eg: true
   gpd.ta.multiSession       ---- TA whether supports multiple sessions at the same time. Eg: false
   gpd.ta.instanceKeepAlive  ---- TA whether is resident in memory.
                                  true is not loaded after loading once.
                                  false is loaded from the REE side each time and TA's global variables will be initialized each time.
   gpd.ta.dataSize           ---- TA heap size, in bytes. TEE_Malloc(), TA can allocate memory size. Eg: 65536
   gpd.ta.stackSize          ---- TA stack size, in bytes. Eg: 16384

4. Makefile must be configured with the following items
   CROSS_COMPILE    ---- Toolchain
   TA_DEV_KIT_DIR   ---- TA development directory that contains the development of TA needed header files, link scripts.
   include $(TA_DEV_KIT_DIR)/mk/ta_common.mak   ---- Compile TA and automatically include sub.mk for this directory
   BINARY           ---- TA's UUID
   TA_NAME          ---- TA's name

5. sub.mk: Compiled configuration file
   srcs-y += xxx.c                         ---- Compile the C file
   srcs-y += xxx.s                         ---- Compile the S file
   subdirs-y += xxx_dir                    ---- Compile subfolders
   incdirs-y += xxx_include                ---- include directory for TA/LIB compile
   cflags-y += -xxx                        ---- C compiler options, such as header files, macro definitions, etc. Eg: -I, -D
   aflags-y += -xxx                        ---- Assembly file compilation options
   cflags-xxx.c-y := -Wno-unused-variable  ---- The specified file with the specified compiler options

6.Makefile of ta and c files can use externel macro
    6.1 Macros which start with CFG_ in secore os ,are transmited to ta Makefile and c files
    6.2 Macros defined in cfg.mak of sdk, are not transmited to ta Makefile and c files. They can be used ,if they are transmited to secure os and start with CFG_.
    6.3 Passing these macro definitions is not a good practice, this is currently done for compatibility.Do not use SDK or safe macro definition 
        in subsequent TA design, and do not couple with the underlying layer.
