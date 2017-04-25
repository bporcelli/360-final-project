ae_sources = lwip_ae_open.c lwip_ae_access.c lwip_ae_stat.c lwip_ae_utimes.c \
	lwip_ae_redirect.c lwip_ae_execve.c lwip_ae_exit.c lwip_ae_readwrite.c \
	lwip_ae_waitpid.c lwip_ae_fork.c lwip_ae_pipe.c lwip_ae_fdManager.c \
	lwip_ae_close.c lwip_ae_mmap.c lwip_ae_dup.c lwip_ae_socket.c

ae_special_header = lwip_ae_syscall_mapping.h

ae_dir = ./ae

base_sources = lwip_access_h.c lwip_access_l.c lwip_chmod_h.c lwip_chmod_l.c \
		lwip_chown_h.c lwip_chown_l.c lwip_execve_h.c lwip_execve_l.c \
		lwip_fork.c lwip_getuid_l.c lwip_ipc_h.c lwip_link_l.c lwip_mkdir_l.c \
		lwip_mknod.c lwip_open_h.c lwip_open_l.c lwip_rename_h.c lwip_rename_l.c \
		lwip_socket_h.c lwip_socket_l.c lwip_statfs_l.c lwip_stat_l.c \
		lwip_unlink_l.c lwip_utimes_l.c

base_special_header = lwip_syscall_mapping.h

base_dir = ./base


tx_sources = lwip_tx.c lwip_tx_open.c

tx_special_header = lwip_tx_syscall_mapping.h

tx_dir = ./tx


rd_sources = lwip_rd.c lwip_rd_getuid.c lwip_rd_pgid.c lwip_rd_unlink.c \
	lwip_rd_execve.c lwip_rd_fork.c lwip_rd_levelManager.c lwip_rd_open.c \
	lwip_rd_recoveryManager.c


rd_special_header = lwip_rd_syscall_mapping.h

rd_dir = ./rd

iso_sources = lwip_iso.c lwip_iso_getuid.c lwip_iso_pgid.c lwip_iso_unlink.c \
	lwip_iso_execve.c lwip_iso_fork.c lwip_iso_levelManager.c lwip_iso_open.c \
	lwip_iso_recoveryManager.c lwip_iso_isoManager.c

iso_special_header = lwip_iso_syscall_mapping.h

iso_dir = ./iso


in_sources = lwip_in_getuid.c lwip_in_open.c lwip_in_execve.c lwip_in_inManager.c lwip_in_futex.c

in_special_header = lwip_in_syscall_mapping.h

in_dir = ./in





