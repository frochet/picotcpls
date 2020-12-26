#define KBUILD_MODNAME "tcpcctrace"
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp.h>
#include <linux/kernel.h>

// eBPF tables to output data
BPF_PERF_OUTPUT(cwnd_change);
BPF_PERF_OUTPUT(timer_calc);
BPF_PERF_OUTPUT(init_event);
BPF_PERF_OUTPUT(mark_lost);
BPF_PERF_OUTPUT(recvmsg);
BPF_PERF_OUTPUT(sendmsg);
BPF_PERF_OUTPUT(tcp_transmit);
BPF_PERF_OUTPUT(tcp_rcv);

static unsigned int jiffiestousecs(const unsigned long j)
{
	/*
	 * Hz usually doesn't go much further MSEC_PER_SEC.
	 * jiffies_to_usecs() and usecs_to_jiffies() depend on that.
	 */
	//BUILD_BUG_ON(HZ > USEC_PER_SEC);

#if !(USEC_PER_SEC % HZ)
	return (USEC_PER_SEC / HZ) * j;
#else
# if BITS_PER_LONG == 32
	return (HZ_TO_USEC_MUL32 * j) >> HZ_TO_USEC_SHR32;
# else
	return (j * HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN;
# endif
#endif
}

/* BIC TCP Parameters */
struct bictcp {
  u32	cnt;		/* increase cwnd by 1 after ACKs */
  u32	last_max_cwnd;	/* last maximum snd_cwnd */
  u32	last_cwnd;	/* the last snd_cwnd */
  u32	last_time;	/* time when updated last_cwnd */
  u32	bic_origin_point;/* origin point of bic function */
  u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
  u32	delay_min;	/* min delay (msec << 3) */
  u32	epoch_start;	/* beginning of an epoch */
  u32	ack_cnt;	/* number of acks */
  u32	tcp_cwnd;	/* estimated tcp cwnd */
  u16	unused;
  u8	sample_cnt;	/* number of samples to decide curr_rtt */
  u8	found;		/* the exit point is found? */
  u32	round_start;	/* beginning of each round */
  u32	end_seq;	/* end_seq of the round */
  u32	last_ack;	/* last time when the ACK spacing is close */
  u32	curr_rtt;	/* the minimum rtt of current round */
};

struct cwnd_info {
  u32 saddr;
  u64 timestamp;
  u32 snd_cwnd;
  u32 pkts_in_flight;
  u32 min_rtt;
  u32 smoothed_rtt;
  u32 latest_rtt;
  u32 rttvar_us;
};

struct init_info {
  u32 saddr;
  u64 timestamp;
  u32 round_start;
  u32 end_seq;
  u32 curr_rtt;
  u8 sample_cnt;
  u32 ssthresh;
  u32 mdev_us;
  u32 icsk_rto;
};

struct timer_info {
  u32 saddr;
  u64 timestamp;
  int type;
  u32 timer;
};

struct pkt_lost {
  u32 saddr;
  u64 timestamp;
  int loss_trigger;
  u32 seq;
};

struct recvmsg_info{
  u32	snd_cwnd;	/* Sending congestion window		*/
  u32	snd_cwnd_cnt;	/* Linear increase counter		*/
  u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
  u32	snd_cwnd_used;
  u32	prior_cwnd;	/* cwnd right before starting loss recovery */
  u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
  u32	prr_out;	/* Total number of pkts sent during Recovery. */
  u32	delivered;	/* Total data packets delivered incl. rexmits */
  u32	lost;		/* Total data packets lost incl. rexmits */
  u32	rcv_wnd;	/* Current receiver window		*/
  u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
  u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
  u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
  u32	lost_out;	/* Lost packets			*/
  u32	sacked_out;	/* SACK'd packets			*/
  u32   saddr;
  u32   daddr;
  u32   len;
  u32   seq;
  u64 timestamp;
};

// trace tcp_transmit

void trace_tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask){
  struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
  struct recvmsg_info info = {};
  info.timestamp = bpf_ktime_get_ns();
  info.len = skb->len;
  info.seq = tcb->seq;	
  info.daddr          = sk->__sk_common.skc_daddr;
  tcp_transmit.perf_submit(ctx, &info, sizeof(info)); 		    
}

// trace tcp_rcv_established
void trace_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb,
			 const struct tcphdr *th){
  struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
  struct recvmsg_info info = {};
  info.timestamp = bpf_ktime_get_ns();
  info.len = skb->data_len;
  info.seq = tcb->seq;	
  info.saddr          = sk->__sk_common.skc_rcv_saddr;
  tcp_rcv.perf_submit(ctx, &info, sizeof(info)); 		    
}
// trace tcp_recvmsg
void trace_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
  struct tcp_sock *tp = tcp_sk(sk);
  struct recvmsg_info info = {};
  info.snd_cwnd       = tp->snd_cwnd;
  info.snd_cwnd_cnt   = tp->snd_cwnd_cnt;
  info.snd_cwnd_clamp = tp->snd_cwnd_clamp;
  info.snd_cwnd_used  = tp->snd_cwnd_used;
  info.prior_cwnd     = tp->prior_cwnd;
  info.prr_delivered     = tp->prr_delivered;
  info.delivered      = tp->delivered;
  info.lost           = tp->lost;
  info.saddr          = sk->__sk_common.skc_rcv_saddr;
  info.len            = len;
  recvmsg.perf_submit(ctx, &info, sizeof(info)); 	
}

// trace tcp_sendmsg
void trace_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size){
  struct tcp_sock *tp = tcp_sk(sk);
  struct recvmsg_info info = {};
  info.snd_cwnd       = tp->snd_cwnd;
  info.snd_cwnd_cnt   = tp->snd_cwnd_cnt;
  info.snd_cwnd_clamp = tp->snd_cwnd_clamp;
  info.snd_cwnd_used  = tp->snd_cwnd_used;
  info.prior_cwnd     = tp->prior_cwnd;
  info.prr_delivered     = tp->prr_delivered;
  info.delivered      = tp->delivered;
  info.lost           = tp->lost;
  info.daddr          = sk->__sk_common.skc_daddr;
  info.len            = size;
  sendmsg.perf_submit(ctx, &info, sizeof(info));
}
// Trace CWND changes during congestion avoidance
void trace_cong_avoid(struct pt_regs *ctx, struct tcp_sock *tp, u32 w, u32 acked) {
  const struct sock *sk = &(tp->inet_conn.icsk_inet.sk);
  u16 family = sk->__sk_common.skc_family;
	
  if (family == AF_INET) {
    struct cwnd_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.saddr = sk->__sk_common.skc_rcv_saddr;

    info.min_rtt = tp->rtt_min.s[0].v;
    info.smoothed_rtt = tp->srtt_us >> 3;
    info.latest_rtt = tp->rack.rtt_us;
    info.rttvar_us = tp->mdev_us;
    info.snd_cwnd = tp->snd_cwnd;
    info.pkts_in_flight = tp->packets_out;
		
    cwnd_change.perf_submit(ctx, &info, sizeof(info));

    const struct inet_connection_sock *icsk = inet_csk(sk);
    struct timer_info info2 = {};
    info2.timestamp = info.timestamp;
    info2.saddr = info.saddr;
		
    info2.type = 3;
    info2.timer = jiffiestousecs(icsk->icsk_rto);

    timer_calc.perf_submit(ctx, &info2, sizeof(info2));
  }
}

// Trace init congestion control
void trace_init_cong_control(struct pt_regs *ctx, struct sock *sk) {
  u16 family = sk->__sk_common.skc_family;
  if (family == AF_INET) {
    struct init_info info = {};
    info.timestamp = bpf_ktime_get_ns();

    const struct tcp_sock *tp = tcp_sk(sk);
    const struct bictcp *ca = inet_csk_ca(sk);
    const struct inet_connection_sock *icsk = inet_csk(sk);

    info.saddr = sk->__sk_common.skc_rcv_saddr;
    info.round_start = ca->round_start;
    info.end_seq = ca->end_seq;
    info.curr_rtt = ca->curr_rtt;
    info.sample_cnt = ca->sample_cnt;
    info.ssthresh = tp->snd_ssthresh;
    info.mdev_us = tp->mdev_us;
    info.icsk_rto = icsk->icsk_rto;		
    init_event.perf_submit(ctx, &info, sizeof(info));
  }
}


// Trace packets marked as lost
int trace_mark_lost(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb){
  u16 family = sk->__sk_common.skc_family;
  if (family == AF_INET) {
    struct pkt_lost info = {};
    struct tcp_skb_cb *tph = TCP_SKB_CB(skb);

    info.timestamp = bpf_ktime_get_ns();
    info.saddr = sk->__sk_common.skc_rcv_saddr;

    info.loss_trigger = 1;
    info.seq = tph->seq;
    info.seq = be32_to_cpu(info.seq);

    mark_lost.perf_submit(ctx, &info, sizeof(info));
    return TC_ACT_OK;
  }
  return 0;
}
