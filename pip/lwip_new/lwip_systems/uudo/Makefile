executable = uudo
target = $(executable)

sources = uudo.c
objects = $(subst .c,.o,$(sources))

COM_DIR = ../../common
com_sources = lwip_debug.c lwip_level.c lwip_utils.c lwip_bufferManager.c strmap.c
com_objects = $(subst .c,.o,$(com_sources))

all_objects = $(objects) $(addprefix $(COM_DIR)/,$(com_objects))

$(executable): $(objects) $(com_objects)
	@$(call preCompileFunc)
	$(CC) $(CPPFLAGS) $(all_objects) -o $(executable)
	@$(call postCompileFunc)

install: $(executable)
	sudo ln -sf /lwip/executables/$(executable) /bin/$(executable)
	sudo cp -vf $(executable) /lwip/executables/
	sudo chown root:root /lwip/executables/$(executable)
	sudo chmod +s /lwip/executables/$(executable)

.PHONY: $(COM_DIR)
$(com_objects): %.o: $(COM_DIR) 
	$(MAKE) --directory=$(COM_DIR) $@

include_dirs += ../../include/common


	
include ../../common.mk

