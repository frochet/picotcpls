#ifndef LOAD_H
#define LOAD_H
int load_bpf_prog(uint8_t *prog_buff, int f_sz, int is_server);
int unload_bpf_cc(void);
#endif
