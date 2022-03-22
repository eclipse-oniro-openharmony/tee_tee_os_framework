SUB_DIRS = oem_gen_csr cm_gen_oem_key oem_asset_pack

all: $(foreach sub_dir,$(SUB_DIRS),do_$(sub_dir))

clean: $(foreach sub_dir,$(SUB_DIRS),clean_$(sub_dir))

clean_%:
	@make -C $* clean

do_%:
	@make -C $* 

.PHONY: all clean clean_% do_%

