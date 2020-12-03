#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define SEC(NAME) __attribute__((section(NAME), used)) 

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

static int (*bpf_map_update_elem)(struct bpf_map_def *map, void *key,
                                  void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static void *(*bpf_map_lookup_elem)(struct bpf_map_def *map, void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 256,
};


SEC("classifier")
int bpf_prog1(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  struct iphdr *iph = data + nh_off;

  if (iph->protocol != 6) {
    return 0;
  }
  /*__u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u32 ip_total_length = iph->tot_len;

  ip_hlen = iph->ihl << 2;

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);


  tcp_hlen = tcph->doff << 2;*/

  int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  long *value;

  value = bpf_map_lookup_elem(&my_map, &index);
  if (value)
  __sync_fetch_and_add(value, skb->len);
  return 0;
}
char _license[] SEC("license") = "GPL";
