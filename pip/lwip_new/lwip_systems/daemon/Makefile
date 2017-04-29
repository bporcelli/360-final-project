include common.mk

executable = daemon
target = $(executable)

sources = daemon.c proxy.c  
objects = $(subst .c,.o,$(sources))

COM_DIR = ../../common
com_sources = lwip_debug.c lwip_level.c lwip_utils.c lwip_redirectHelper.c lwip_bufferManager.c \
		thpool.c strmap.c

com_objects = $(subst .c,.o,$(com_sources))

base_objects = $(subst .c,.o,$(base_sources))

all_objects = $(objects) $(addprefix $(COM_DIR)/,$(com_objects)) \
		$(addprefix $(base_dir)/,$(base_objects)) \

all_dirs = $(base_dir) #$(iso_dir)

$(executable): $(objects) $(com_objects) $(all_dirs)
	@$(call preCompileFunc)
	$(CC) -o $(executable) $(CPPFLAGS) $(all_objects) 
	@$(call postCompileFunc)

.PHONY: $(COM_DIR) $(all_dirs)

$(com_objects): %.o: $(COM_DIR) 
	$(MAKE) --directory=$(COM_DIR) $@

$(base_dir):
	$(MAKE) --directory=$(base_dir) $(base_objects)


include_dirs += ../../include/common $(all_dirs) ./

install: $(executable)
	sudo cp -vf $(executable) /lwip/executables/
	sudo chown root:root /lwip/executables/$(executable) # daemon must be setuid root
	sudo chmod +s /lwip/executables/$(executable)
	
include ../../common.mk



