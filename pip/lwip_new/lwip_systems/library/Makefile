SHELL := /bin/bash
include common.mk

LIB = libextlib.so.1
library = $(LIB)

LIB_FLAGS = -fPIC -shared -Wl,-z,defs

sources = lwip_delegator_connection.c lwip_extlib.c lwip_redirect.c \
	lwip_syscall_ftb.c
objects = $(subst .c,.o,$(sources))

com_dir = ../../common
com_sources = lwip_debug.c lwip_level.c lwip_utils.c lwip_redirectHelper.c \
	lwip_notifier.c lwip_in_utils.c lwip_trusted.c \
	lwip_trackOpen.c ac.c strmap.c lwip_bufferManager.c lwip_extendedLogging.c

com_objects = $(subst .c,.o,$(com_sources))

all_dirs = $(com_dir) $(base_dir)


base_objects = $(subst .c,.o,$(base_sources))

all_objects = $(objects)\
	$(addprefix $(base_dir)/,$(base_objects)) \
	$(addprefix $(com_dir)/,$(com_objects)) 


$(LIB):	$(all_dirs) $(objects)
	@$(call preCompileFunc)
	$(CC) $(CPPFLAGS) $(LIB_FLAGS) $(all_objects) -o $(LIB)
	@$(call postCompileFunc)

compile: $(LIB)

install: replace


replace: $(LIB)
	./replaceLib.sh


.PHONY: $(all_dirs)

$(com_dir):
	$(MAKE) --directory=$(com_dir) $(com_objects)

$(base_dir):
	$(MAKE) --directory=$(base_dir) $(base_objects) $(base_special_header)

include_dirs += ../../include/common $(base_dir) ./

extra_clean += $(addprefix $(base_dir)/,$(base_special_header))

include ../../common.mk

clean::
	-for d in $(all_dirs); do ($(MAKE) --directory=$$d clean ); done
	$(RM) $(objects) $(executable) $(library) $(dependencies) $(extra_clean) $(all_objects)
	

