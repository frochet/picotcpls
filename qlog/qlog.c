// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>
#include "qlog.h"

static int loadbpf = 0;

int qlog_load_bpf_prog(char *int_f)
{
  char filename[256];
  FILE *f;
  int i, sock;
  snprintf(filename, sizeof(filename), "%s", "qlog_kern.o");
  if (load_bpf_file(filename)) {
    printf("%s", bpf_log_buf);
    return 1;
  }
  sock = open_raw_sock(int_f);
  assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd,
			  sizeof(prog_fd[0])) == 0);
  for (;;) {
    long long tcp_cnt, last_cnt;
    int key;
    key = IPPROTO_TCP;
    assert(bpf_map_lookup_elem(map_fd[0], &key, &tcp_cnt) == 0);
    if(last_cnt != tcp_cnt)
       printf("TCP %lld\n", tcp_cnt);
    assert(bpf_map_lookup_elem(map_fd[1], &key, &tcp_cnt) == 0);
    if(last_cnt != tcp_cnt)
       printf("TCP2 %lld\n", tcp_cnt);
    last_cnt = tcp_cnt;
  }
}
