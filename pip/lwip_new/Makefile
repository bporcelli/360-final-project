dirs = lwip_systems utils

.PHONY: $(dirs) clean


compile: config_file $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d compile ); done

clean: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d clean ); done
	-rm -f ./include/common/lwip_common.h

install: config_file $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d install ); done
	

	
config_file: ./include/common/lwip_common.h.template


./include/common/lwip_common.h.template: 
	./configure.sh




