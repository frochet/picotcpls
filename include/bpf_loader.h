#ifndef bpf_loader_h
#define bpf_loader_h
#include "picotypes.h"
#include "picotcpls.h"
#include "picotls.h"

#define BPF_FOLDER "/sys/fs/bpf/"

int register_struct_ops(ptls_tcpls_t *option);
int load_bpf_prog(ptls_tcpls_t *option, const char *bpf_fs_pinfile);

#endif
