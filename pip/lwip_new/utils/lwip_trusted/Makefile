executable = lwip_trusted
target = $(executable)

sources = lwip_trusted.c
objects = $(subst .c,.o,$(sources))

COM_DIR = ../../common
com_sources = lwip_debug.c #lwip_level.c lwip_utils.c
com_objects = $(subst .c,.o,$(com_sources))

all_objects = $(objects) $(addprefix $(COM_DIR)/,$(com_objects))

$(executable): $(objects) $(COM_DIR)
	@$(call preCompileFunc)
	$(CC) $(CPPFLAGS) $(all_objects) -o $(executable)
	@$(call postCompileFunc)


install: $(executable)
	sudo ln -sf /lwip/executables/$(executable) /bin/$(executable)
	sudo mv -v $(executable) /lwip/executables/$(executable)


.PHONY: $(COM_DIR)
$(COM_DIR):
	$(MAKE) --directory=$(COM_DIR) $(com_objects)

include_dirs += ../../include/common
	
include ../../common.mk

