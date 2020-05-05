#include <linux/err.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>


int load_bpf_prog(uint8_t *base, size_t len){
	struct bpf_object *obj;
	struct bpf_program  *pos;
	__u32 ifindex = 0;
        struct bpf_link *link;
	struct bpf_map *map;
	const struct bpf_map_def *def;
	int err = 0;
	obj = bpf_object__open_mem(base, len, NULL);
	if (!obj) {
		perror("failed to open object file");
		return -1;
	}

	bpf_object__for_each_program(pos, obj) {
		enum bpf_prog_type prog_type = bpf_program__get_type(pos);
		enum bpf_attach_type expected_attach_type =
			bpf_program__get_expected_attach_type(pos);
		bpf_program__set_ifindex(pos, ifindex);
		bpf_program__set_type(pos, prog_type);
		bpf_program__set_expected_attach_type(pos, expected_attach_type);
	}

	err = bpf_object__load(obj);
	if (err) {
		perror("failed to load object file");
		return -1;
	}

	bpf_object__for_each_map(map, obj) {
		def = bpf_map__def(map);
		if (def->type != BPF_MAP_TYPE_STRUCT_OPS)
			continue;

		link = bpf_map__attach_struct_ops(map);
		if (!link) {
			printf("can't register struct_ops %s: %s",
			      bpf_map__name(map),
			      strerror(-PTR_ERR(link)));
			continue;
		}
		bpf_link__disconnect(link);
		bpf_link__destroy(link);

	}
	bpf_object__close(obj);
	return err;
}
