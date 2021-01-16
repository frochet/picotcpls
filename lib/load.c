/** Inspired from linux bpftool code ***/

#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "load.h"

#define STRUCT_OPS_VALUE_PREFIX "bpf_struct_ops_"

static int struct_ops_id = -1;
static struct btf *btf_vmlinux;

struct map_replace {
  int idx;
  int fd;
  char *name;
};


static const struct btf *get_btf_vmlinux(void){
  if (btf_vmlinux)
    return btf_vmlinux;

  btf_vmlinux = libbpf_find_kernel_btf();
  if (!btf_vmlinux)
    perror("struct_ops requires kernel CONFIG_DEBUG_INFO_BTF=y");
  return btf_vmlinux;
}

static const char *get_kern_struct_ops_name(const struct bpf_map_info *info){
  const struct btf *kern_btf;
  const struct btf_type *t;
  const char *st_ops_name;

  kern_btf = get_btf_vmlinux();
  if (!kern_btf)
    return "<btf_vmlinux_not_found>";

  t = btf__type_by_id(kern_btf, info->btf_vmlinux_value_type_id);
  st_ops_name = btf__name_by_offset(kern_btf, t->name_off);
  st_ops_name += strlen(STRUCT_OPS_VALUE_PREFIX);
  return st_ops_name;
}

int load_bpf_prog(uint8_t *prog_buff, int f_sz, int is_server){
  enum bpf_prog_type common_prog_type = BPF_PROG_TYPE_UNSPEC;
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
    .relaxed_maps = true,
  );
  struct bpf_object_load_attr load_attr = { 0 };
  enum bpf_attach_type expected_attach_type;
  struct map_replace *map_replace = NULL;
  struct bpf_program  *pos;
  unsigned int old_map_fds = 0;
  struct bpf_object *obj;
  struct bpf_map *map;
  unsigned int i, j;
  __u32 ifindex = 0;
  int idx, err;
  const struct bpf_map_def *def;
  struct bpf_map_info info = {};
  __u32 info_len = sizeof(info);
  int nr_maps = 0;
  struct bpf_link *link;
  obj = bpf_object__open_mem(prog_buff, f_sz, &open_opts);
  if (!obj) {
    printf("failed to open object file");
    goto err_free_reuse_maps;
  }
  
  bpf_object__for_each_program(pos, obj) {
    enum bpf_prog_type prog_type = common_prog_type;
    if (prog_type == BPF_PROG_TYPE_UNSPEC) {
      const char *sec_name = bpf_program__title(pos, false);
      err = libbpf_prog_type_by_name(sec_name, &prog_type, &expected_attach_type);
      if (err < 0)
        goto err_close_obj;
    }
    bpf_program__set_ifindex(pos, ifindex);
    bpf_program__set_type(pos, prog_type);
    bpf_program__set_expected_attach_type(pos, expected_attach_type);
  }
  j = 0;
  while (j < old_map_fds && map_replace[j].name) {
    i = 0;
    bpf_object__for_each_map(map, obj) {
      if (!strcmp(bpf_map__name(map), map_replace[j].name)) {
        map_replace[j].idx = i;
        break;
      }
      i++;
    }
    if (map_replace[j].idx == -1) {
      fprintf(stderr, "unable to find map '%s'", map_replace[j].name);
      goto err_close_obj;
    }
    j++;
  }
  j = 0;
  idx = 0;
  bpf_object__for_each_map(map, obj) {
    if (!bpf_map__is_offload_neutral(map))
      bpf_map__set_ifindex(map, ifindex);
    if (j < old_map_fds && idx == map_replace[j].idx) {
      err = bpf_map__reuse_fd(map, map_replace[j++].fd);
      if (err) {
        fprintf(stderr, "unable to set up map reuse: %d", err);
        goto err_close_obj;
      }
      if (j < old_map_fds && map_replace[j].idx == idx) {
        printf("replacement for map idx %d specified more than once", idx);
        goto err_close_obj;
      }
    }
    idx++;
  }
  if (j < old_map_fds) {
    fprintf(stderr, "map idx '%d' not used", map_replace[j].idx);
    goto err_close_obj;
  }

  load_attr.obj = obj;
  load_attr.log_level = 1 + 2 + 4;

  err = bpf_object__load_xattr(&load_attr);
  if (err) {
    fprintf(stderr, "failed to load object file");
    goto err_close_obj;
  }
  if(is_server)
    bpf_object__for_each_map(map, obj) {
      def = bpf_map__def(map);
      if (def->type != BPF_MAP_TYPE_STRUCT_OPS)
        continue;
      link = bpf_map__attach_struct_ops(map);
      if (!link) {
        fprintf(stderr, "Error: Unable to attach map_struct_ops\n");
        continue;
      }
      nr_maps++;
      bpf_link__disconnect(link);
      bpf_link__destroy(link);

      if (bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &info_len))
        fprintf(stderr, "Registered %s but can't find id: %s", bpf_map__name(map), strerror(errno));
      get_kern_struct_ops_name(&info);
      struct_ops_id = info.id;
    }
  bpf_object__close(obj);
  for (i = 0; i < old_map_fds; i++)
    close(map_replace[i].fd);
  free(map_replace);
  return 0;
err_close_obj:
  bpf_object__close(obj);
err_free_reuse_maps:
  for (i = 0; i < old_map_fds; i++)
    close(map_replace[i].fd);
  free(map_replace);
  return -1;
}

int unload_bpf_cc(void){
  int zero = 0;
  if(struct_ops_id < 0)
    return -1;
  int fd = bpf_map_get_fd_by_id(struct_ops_id);
  if (bpf_map_delete_elem(fd, &zero)){
    fprintf(stderr, "can not delete map\n");
    return -1;
  }
  close(fd);
  return 0;
}
