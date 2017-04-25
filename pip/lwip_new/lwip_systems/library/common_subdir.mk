objects = $(subst .c,.o,$(sources))

include_dirs = ../../../include/common ../

awk_file ?= process_mapping.awk

special_header_src = $(subst .h,.c,$(special_header))



$(special_header): $(special_header_src) $(awk_file)
	cpp $(special_header_src) $(addprefix -I ,$(include_dirs)) | gawk -f $(awk_file) > $@

$(awk_file):
	m4 -P -DPRE_HANDLER_ENTRY=$(awk_pre_mapping_name) -DPOST_HANDLER_ENTRY=$(awk_post_mapping_name) ../process_mapping.awk > $@

target = $(objects) $(special_header)

extra_clean += $(special_header) $(awk_file)


