MV           := mv -f
RM           := rm -f
SED          := sed
CC           := gcc -m32 

objects      := $(subst .c,.o,$(sources))
dependencies := $(subst .c,.d,$(sources))
#dependencies += $(subst .o,.d,$(all_objects))

#include_dirs += .. ../include/common
CPPFLAGS     += $(addprefix -I ,$(include_dirs)) -ggdb -Wall -Werror -D_GNU_SOURCE -Wl,--no-as-needed -lpthread


common_header += lwip_common.h

target	?= $(objects)
target += $(common_header)

vpath %.h $(include_dirs)
vpath lwip_common.h.template $(include_dirs)

all: $(target) $(common_header)

$(addsuffix /lwip_common.h, $(include_dirs)): lwip_common.h.template
	~/20111230/20111228/lwip_new/configure.sh

%.o: %.c
	$(CC) $(CPPFLAGS) -c $<   

.PHONY: clean
clean::
	-for d in $(all_dirs); do ($(MAKE) --directory=$$d clean ); done
	$(RM) $(objects) $(executable) $(library) $(dependencies) $(extra_clean) $(all_objects) 


ifneq "$(MAKECMDGOALS)" "clean"
  -include $(dependencies)
endif


compile: $(executable)


%.d: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -M $< |      \
	$(SED) 's,\($*\.o\) *:,\1 $@: ,' > $@.tmp
	$(MV) $@.tmp $@


define preCompileFunc
  echo "pre"
  restoreLib
endef

define postCompileFunc
  echo "post"
  replaceLib
endef



