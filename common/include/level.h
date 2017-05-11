#ifndef _SIP_LEVEL_H
#define _SIP_LEVEL_H

#define SIP_LV_HIGH 1
#define SIP_LV_LOW -1

int sip_fd_to_level(int fd);
int sip_downgrade_fd(int fd);
int sip_path_to_level(char* path);
int sip_level(void);

#endif
