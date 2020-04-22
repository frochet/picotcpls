/* inpired from linux/tools/bpftool/prog.c*/

#include "bpf_load.h"
#include "bpf_insn.h"
#include <errno.h>
#include <stdio.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/mount.h>
#include <linux/err.h>

#include <sys/vfs.h>
#include <linux/magic.h>
#include "bpf_loader.h"




#define ERR_MAX_LEN 10
#define STRUCT_OPS_VALUE_PREFIX "bpf_struct_ops_"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static struct btf *btf_vmlinux;


static int
get_prog_type_by_name(const char *name, enum bpf_prog_type *prog_type,
		      enum bpf_attach_type *expected_attach_type)
{
	int ret;

	ret = libbpf_prog_type_by_name(name, prog_type, expected_attach_type);
	if (!ret)
		return ret;

	/* libbpf_prog_type_by_name() failed, let's re-run with debug level */
	ret = libbpf_prog_type_by_name(name, prog_type, expected_attach_type);
	

	return ret;
}

static int
mnt_fs(const char *target, const char *type, char *buff, size_t bufflen)
{
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			snprintf(buff, bufflen,
				 "mount --make-private %s failed: %s",
				 target, strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			snprintf(buff, bufflen,
				 "mount --bind %s %s failed: %s",
				 target, target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount(type, target, type, 0, "mode=0700")) {
		snprintf(buff, bufflen, "mount -t %s %s %s failed: %s",
			 type, type, target, strerror(errno));
		return -1;
	}

	return 0;
}


static bool is_bpffs(char *path)
{
	struct statfs st_fs;

	if (statfs(path, &st_fs) < 0)
		return false;

	return (unsigned long)st_fs.f_type == BPF_FS_MAGIC;
}

static const struct btf *get_btf_vmlinux(void)
{
	if (btf_vmlinux)
		return btf_vmlinux;

	btf_vmlinux = libbpf_find_kernel_btf();
	if (IS_ERR(btf_vmlinux))
		perror("struct_ops requires kernel CONFIG_DEBUG_INFO_BTF=y");

	return btf_vmlinux;
}

static const char *get_kern_struct_ops_name(const struct bpf_map_info *info)
{
	const struct btf *kern_btf;
	const struct btf_type *t;
	const char *st_ops_name;

	kern_btf = get_btf_vmlinux();
	if (IS_ERR(kern_btf))
		return "<btf_vmlinux_not_found>";

	t = btf__type_by_id(kern_btf, info->btf_vmlinux_value_type_id);
	st_ops_name = btf__name_by_offset(kern_btf, t->name_off);
	st_ops_name += strlen(STRUCT_OPS_VALUE_PREFIX);

	return st_ops_name;
}
static int mount_bpffs_for_pin(const char *name)
{
	char err_str[ERR_MAX_LEN];
	char *file;
	char *dir;
	int err = 0;

	file = malloc(strlen(name) + 1);
	strcpy(file, name);
	dir = dirname(file);

	if (is_bpffs(dir))
		
		goto out_free;
	err = mnt_fs(dir, "bpf", err_str, ERR_MAX_LEN);
	if (err) {
		err_str[ERR_MAX_LEN - 1] = '\0';
		printf("can't mount BPF file system to pin the object (%s): %s",
		      name, err_str);
	}

out_free:
	free(file);
	return err;
}


int load_bpf_prog(ptls_tcpls_t *option, const char *bpf_fs_pinfile){
	enum bpf_prog_type common_prog_type = BPF_PROG_TYPE_UNSPEC;
	int err;
	struct bpf_object *obj;
	struct bpf_program  *pos;
	enum bpf_attach_type expected_attach_type;
	__u32 ifindex = 0;
	struct bpf_object_load_attr load_attr = { 0 };
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.relaxed_maps = true,
	);
	obj = bpf_object__open_mem(option->data->base, 
			option->data->len, &open_opts);
	if (!obj) {
		perror("failed to open object");
		return -1;
	}

	bpf_object__for_each_program(pos, obj) {
		enum bpf_prog_type prog_type = common_prog_type;
		const char *sec_name = bpf_program__title(pos, false);

		err = get_prog_type_by_name(sec_name, &prog_type,
						    &expected_attach_type);
		if(err<0)
			goto err_close_obj;

		bpf_program__set_ifindex(pos, ifindex);
		bpf_program__set_type(pos, prog_type);
		bpf_program__set_expected_attach_type(pos, expected_attach_type);

	}

	load_attr.obj = obj;
	load_attr.log_level = 1 + 2 + 4;

	err = bpf_object__load_xattr(&load_attr);
	if (err) {
		perror("failed to load object file");
		goto err_close_obj;
	}

	err = mount_bpffs_for_pin(bpf_fs_pinfile);
	if (err)
		goto err_close_obj;

	err = bpf_object__pin_programs(obj, bpf_fs_pinfile);
	 if (err) {
		perror("failed to pin all programs");
		goto err_close_obj;
	}

err_close_obj:
	bpf_object__close(obj);
	return err;
}

int register_struct_ops(ptls_tcpls_t *option){
	const struct bpf_map_def *def;
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int nr_errs = 0, nr_maps = 0;
	struct bpf_link *link;
	struct bpf_map *map;
	struct bpf_object *obj;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.relaxed_maps = true,
	);
	obj = bpf_object__open_mem(option->data->base, 
			option->data->len, &open_opts);
	if (!obj) {
		perror("failed to open object file");
		return -1;
	}
	if (bpf_object__load(obj)) {
		bpf_object__close(obj);
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
			nr_errs++;
			continue;
		}
		nr_maps++;

		bpf_link__disconnect(link);
		bpf_link__destroy(link);

		if (!bpf_obj_get_info_by_fd(bpf_map__fd(map), &info,
					    &info_len))
			printf("Registered %s %s id %u",
			       get_kern_struct_ops_name(&info),
			       bpf_map__name(map),
			       info.id);
		else
			/* Not p_err.  The struct_ops was attached
			 * successfully.
			 */
			printf("Registered %s but can't find id: %s",
			       bpf_map__name(map), strerror(errno));
	}

	bpf_object__close(obj);

	if (nr_errs)
		return -1;

	if (!nr_maps) {
		perror("no struct_ops found in");
		return -1;
	}
	btf__free(btf_vmlinux);
	return 0;
}

/*int main(int argc, char **argv) {
	int err = -1;
	if(argc !=3){
		printf("%s <bpf_file_path> <bpf_fs_pinfile>\n", argv[0]);
		return 0;
	}
	err = load_bpf_prog(argv[1], argv[2]);	
	if(err){
		printf("Unable to load program from %s.o\n",argv[1]);
		return -1;
	}
	err = register_struct_ops(argv[1]);

	if(err){
		printf("Unable to register struct_ops %s.o\n",argv[1]);
	}
	btf__free(btf_vmlinux);
  	return err;
}*/


