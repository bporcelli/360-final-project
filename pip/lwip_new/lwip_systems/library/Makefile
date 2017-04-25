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
	lwip_notifier.c lwip_in_utils.c lwip_trusted.c lwip_ae_utils.c \
	lwip_trackOpen.c ac.c strmap.c lwip_bufferManager.c lwip_extendedLogging.c

com_objects = $(subst .c,.o,$(com_sources))

all_dirs = $(com_dir) $(base_dir) #$(tx_dir) $(ae_dir) $(rd_dir) $(iso_dir) $(in_dir)


ae_objects = $(subst .c,.o,$(ae_sources))
base_objects = $(subst .c,.o,$(base_sources))
tx_objects = $(subst .c,.o,$(tx_sources))
rd_objects = $(subst .c,.o,$(rd_sources))
iso_objects = $(subst .c,.o,$(iso_sources))
in_objects = $(subst .c,.o,$(in_sources))

all_objects = $(objects)\
	$(addprefix $(base_dir)/,$(base_objects)) \
	$(addprefix $(com_dir)/,$(com_objects)) 

#\
	$(addprefix $(tx_dir)/,$(tx_objects)) \
	$(addprefix $(rd_dir)/,$(rd_objects)) \
	$(addprefix $(iso_dir)/,$(iso_objects)) \
	$(addprefix $(in_dir)/,$(in_objects)) \
	$(addprefix $(ae_dir)/,$(ae_objects)) 
	

#$(LIB): $(ae_special_header) $(base_special_header) $(tx_special_header) $(rd_special_header) \
#	$(objects) $(ae_objects) $(base_objects) $(com_objects) $(tx_objects) $(rd_objects)


$(LIB):	$(all_dirs) $(objects)
	@$(call preCompileFunc)
	$(CC) $(CPPFLAGS) $(LIB_FLAGS) $(all_objects) -o $(LIB)
	@$(call postCompileFunc)

compile: $(LIB)

install: replace

#$(all_dirs) $(objects)
#	restoreLib
#	$(CC) $(CPPFLAGS) $(LIB_FLAGS) $(all_objects) -o $(LIB)
#	sudo cp -v $(LIB) /lib
#	replaceLib

replace: $(LIB)
	./replaceLib.sh


.PHONY: $(all_dirs)

$(com_dir):
	$(MAKE) --directory=$(com_dir) $(com_objects)

$(ae_dir):
	$(MAKE) --directory=$(ae_dir)  $(ae_special_header) $(ae_objects)

$(base_dir):
	$(MAKE) --directory=$(base_dir) $(base_objects) $(base_special_header)

$(tx_dir):
	$(MAKE) --directory=$(tx_dir) $(tx_objects) $(tx_special_header)

$(rd_dir):
	$(MAKE) --directory=$(rd_dir) $(rd_objects) $(rd_special_header)

$(iso_dir):
	$(MAKE) --directory=$(iso_dir) $(iso_objects) $(iso_special_header)

$(in_dir):
	$(MAKE) --directory=$(in_dir) $(in_objects) $(in_special_header)

include_dirs += ../../include/common $(ae_dir) $(base_dir) $(tx_dir) $(rd_dir) $(iso_dir) $(in_dir) ./

extra_clean += $(addprefix $(ae_dir)/,$(ae_special_header)) $(addprefix $(tx_dir)/,$(tx_special_header)) \
	 $(addprefix $(base_dir)/,$(base_special_header)) $(addprefix $(rd_dir)/,$(rd_special_header)) \
	 $(addprefix $(iso_dir)/,$(iso_special_header))


#vpath %.h $(include_dirs)
#vpath lwip_common.h.template $(include_dirs)

#../../include/common/lwip_common.h: lwip_common.h.template
#	~/20111230/20111228/lwip_new/configure.sh




include ../../common.mk

clean::
	-for d in $(all_dirs); do ($(MAKE) --directory=$$d clean ); done
	$(RM) $(objects) $(executable) $(library) $(dependencies) $(extra_clean) $(all_objects)
	

