dirs = lwip_downgradeFile lwip_showLevel lwip_trusted

.PHONY: $(dirs) clean


clean: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d clean ); done

install: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d install ); done
	
compile: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d compile ); done




