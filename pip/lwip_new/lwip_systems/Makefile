dirs = daemon library uudo
	# lwip_2uid_wrapper lwip_ae lwip_iso lwip_lxc_wrapper \
	lwip_rd uudo root_daemon rudo lwip_nonlxc_wrapper


.PHONY: $(dirs) clean


clean: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d clean ); done

install: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d install ); done
	
compile: $(dirs)
	-for d in $(dirs); do ($(MAKE) --directory=$$d compile ); done
	




