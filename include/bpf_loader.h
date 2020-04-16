#ifndef bpf_loader_h
#define bpf_loader_h

int register_struct_ops(const char *bpf_file);
int load_bpf_prog(const char *bpf_file, const char *bpf_fs_pinfile);

#endif
