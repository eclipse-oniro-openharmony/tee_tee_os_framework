1. 输入make，编译出 $(TA_UUID).bin, $(TA_UUID).elf。
    1.1 默认输出目录 $(CURDIR)/out
    1.2 $(TA_UUID).bin 用于trustedcore，加上manifest.txt中内容，使用签名工具签名后，成为动态TA。
    1.3 $(TA_UUID).elf 用于trustedcore

2. 输入make clean， 删除编译生成的文件。

3. manifest.txt: Trustedcore 动态TA的属性描述文件。
   gpd.ta.appID              ---- TA 的UUID
   gpd.ta.service_name       ---- TA 的名字， 如: dynamic_load_demo
   gpd.ta.singleInstance     ---- TA 是否单实例。如: true
   gpd.ta.multiSession       ---- TA 是否支持同时多个session。 如: false
   gpd.ta.instanceKeepAlive  ---- TA 是否常驻内存。
                                  true  则加载一次后就不再加载。
                                  false 则每次都从REE侧加载，此时TA的全局变量每次都会初始化。
   gpd.ta.dataSize           ---- TA 堆大小，单位字节。TEE_Malloc(), TA可以分配内存的大小。 如: 65536
   gpd.ta.stackSize          ---- TA 栈大小，单位字节。如: 16384

4. Makefile 必须配置以下项：
   CROSS_COMPILE    ---- 工具链(Trustedcore的工具链必须要是特定的，不能随意更改)
   TA_DEV_KIT_DIR   ---- TA的开发目录，即包含开发TA所需要的头文件，链接脚本等的目录。
   include $(TA_DEV_KIT_DIR)/mk/ta_common.mak
   BINARY           ---- TA的UUID
   TA_NAME          ---- TA的名字

5. sub.mk: 编译的配置文件
   srcs-y += xxx.c                         ---- 编译C文件
   srcs-y += xxx.s                         ---- 编译S文件
   subdirs-y += xxx_dir                    ---- 编译子文件夹
   incdirs-y += xxx_include                ---- 编译会查找的头文件目录
   cflags-y += -xxx                        ---- C编译选项，如头文件，宏定义等,如： -I, -D
   aflags-y += -xxx                        ---- 汇编文件编译选项

6. TA的Makefile和C文件可用外部宏定义
    6.1 所有安全OS中CFG_开头的宏定义都会传递到TA的Makefile（sub.mk)中，也会传递到C文件中
    6.2 SDK的cfg.mak中的定义不会传递到TA的Makefile和C文件中，但是如果传递到了安全OS中且以CFG开头，则可以使用。
    6.3 传递这些宏定义不是一个好的做法，目前这么处理是为了兼容，后续TA设计不要使用SDK或者安全的宏定义，不要和底层耦合。

