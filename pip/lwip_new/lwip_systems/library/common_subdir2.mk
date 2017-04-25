objects = $(subst .c,.o,$(sources))

include_dirs = ../../../include/common ../

awk_file ?= process_mapping2.awk

special_header_src = $(subst .h,.c,$(special_header))



$(special_header): $(special_header_src) $(awk_file)
	cpp $(special_header_src) $(addprefix -I ,$(include_dirs)) | awk -f $(awk_file) > $@

$(awk_file): ../process_mapping2.awk
	m4 -DHIGH_PRE_HANDLER_ENTRY=$(awk_high_pre_mapping_name) -DHIGH_POST_HANDLER_ENTRY=$(awk_high_post_mapping_name) \
	-DLOW_PRE_HANDLER_ENTRY=$(awk_low_pre_mapping_name) -DLOW_POST_HANDLER_ENTRY=$(awk_low_post_mapping_name) ../process_mapping2.awk > $@

target = $(objects) $(special_header)

extra_clean += $(special_header) $(awk_file)


