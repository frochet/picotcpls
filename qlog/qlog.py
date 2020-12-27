from __future__ import print_function, division
from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import time as ti
import json
import ctypes
import sys
import os

bpf = BPF(src_file="qlog_tcp.c")

cc_cmd = os.popen('sysctl net.ipv4.tcp_congestion_control')
cc = cc_cmd.readline()
if "cubic" in cc:
  event_cong_avoid = "bictcp_cong_avoid"
else:
  if "reno" in cc:
    event_cong_avoid = "tcp_reno_cong_avoid"
  
bpf.attach_kretprobe(event=event_cong_avoid, fn_name="trace_cong_avoid")
bpf.attach_kretprobe(event="tcp_init_buffer_space", fn_name="trace_init_cong_control")
bpf.attach_kretprobe(event="tcp_mark_skb_lost", fn_name="trace_mark_lost")
bpf.attach_kprobe(event="tcp_recvmsg", fn_name="trace_recvmsg")
bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_sendmsg")
bpf.attach_kretprobe(event="__tcp_transmit_skb", fn_name="trace_tcp_transmit_skb") 
bpf.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv_established")

qlog = {
  "qlog_version": "draft-01",
  "traces": [
    {
      "common_fields": {
        "reference_time": -1
      },
      "configuration": {"time_units": "ms"},
      "event_fields": [
        "relative_time",
        "category",
        "event_type",
        "data"
      ],
      "events": [
        ["0", "transport", "datagrams_received", {"byte_length": 1280, "count": 1}]
      ],
      "vantage_point": {
        "name": "tcpls",
        "type": "server"
      }
    }
  ]
}

# final packet event to generate congestion view in QVis
final_pkt_evt = ["0", "transport", "packet_received", {
	"packet_type": "1RTT", "header": {
		"packet_number": "2656", "packet_size": 30, "dcid": "tcpebpf", "scid": ""
		}, 
		"frames": [{"error_code": 0, "error_space": "application", "frame_type": "connection_close", "raw_error_code": 0, "reason": ""}]}]

# Congestion algorithm states
ca_states = {}
ca_states[0] = "TCP_CA_Open"
ca_states[1] = "TCP_CA_Disorder"
ca_states[2] = "TCP_CA_CWR"
ca_states[3] = "TCP_CA_Recovery"
ca_states[4] = "TCP_CA_Loss"

# CWND events
cwnd_event_types = {}
cwnd_event_types[0] = "CA_EVENT_TX_START"
cwnd_event_types[1] = "CA_EVENT_CWND_RESTART"
cwnd_event_types[2] = "CA_EVENT_COMPLETE_CWR"
cwnd_event_types[3] = "CA_EVENT_LOSS"
cwnd_event_types[4] = "CA_EVENT_ECN_NO_CE"
cwnd_event_types[5] = "CA_EVENT_ECN_IS_CE"

# Get timestamp of kernel boot
with open('/proc/uptime', 'r') as f:
	uptime_s = float(f.readline().split()[0])
	start_time = ti.time() - uptime_s

# Reference times for server
reference_time = -1

# Calculate time delta of event
def setTimeInfo(timestamp):
	time = 0.0
	global reference_time
	if reference_time == -1:
		reference_time = start_time + (ctypes.c_float(timestamp).value / 1000000000)
		reference_time = ti.time()
		qlog["traces"][0]["common_fields"]["reference_time"] = reference_time
	time = reference_time - (start_time + (ctypes.c_float(timestamp).value / 1000000000))
	return reference_time - ti.time()
	
prev_met_upd_t = 0
# Log new CWND values
def print_cwnd_change(cpu, data, size):
  event = bpf["cwnd_change"].event(data)
  # get sender's IP
  sender = inet_ntop(AF_INET, pack('I', event.saddr))
  # Filter out IP for simulators since all kernel activity is logged
  if sender.__contains__("192.168.3.100") or sender.__contains__("192.168.0.100"):
    global prev_met_upd_t
    output_arr = []
    output_arr.append("%.6f" % (abs(prev_met_upd_t) * 1000))
    prev_met_upd_t = setTimeInfo(event.timestamp)
    output_arr.append("recovery")
    output_arr.append("metrics_updated")
    output_arr.append(
      {
        "cwnd": str(event.snd_cwnd),
        "bytes_in_flight": str(event.pkts_in_flight),
        "min_rtt": "%.2f" % (event.min_rtt / 1000),
        "smoothed_rtt": "%.2f" % (event.smoothed_rtt / 1000),
        "latest_rtt": "%.2f" % (event.latest_rtt / 1000),
        "rtt_variance": "%.2f" % (event.rttvar_us / 1000)
      }
    )
    qlog["traces"][0]["events"].append(output_arr)
    global final_pkt_evt
    final_pkt_evt[0] = output_arr[0]

# Log initial congestion control values
def print_init_cong_control(cpu, data, size):
  event = bpf["init_event"].event(data)
  sender = inet_ntop(AF_INET, pack('I', event.saddr))
  if sender.__contains__("192.168.3.100") or sender.__contains__("192.168.0.100"):
    time = setTimeInfo(event.timestamp)
    output_arr = []
    output_arr.append("%.6f" % (abs(time) * 1000))
    output_arr.append("transport")
    output_arr.append("parameters_set")
    output_arr.append(
      {
        "begin_of_round": str(event.round_start),
        "end_seq_round": str(event.end_seq),
        "min_rtt_curr_round": str(event.curr_rtt),
        "samples_needed_curr_rtt": str(event.sample_cnt),
        "initial_ssthresh": str(event.ssthresh),
        "deviation_rtt_ms": "%.2f" % (event.mdev_us / 1000),
        "intial_RTO": str(event.icsk_rto)
      }
    )
    qlog["traces"][0]["events"].append(output_arr)
    global final_pkt_evt
    final_pkt_evt[0] = output_arr[0]

# Log loss triggers for packets that were declared lost
def print_mark_lost(cpu, data, size):
  event = bpf["mark_lost"].event(data)
  sender = inet_ntop(AF_INET, pack('I', event.saddr))
  if sender.__contains__("192.168.3.100") or sender.__contains__("192.168.0.100"):
    time = setTimeInfo(event.timestamp)
    output_arr = []
    output_arr.append("%.6f" % (abs(time) * 1000))
    output_arr.append("recovery")
    output_arr.append("packet_lost")

    trigger = ""
    if event.loss_trigger == 1:
      trigger = "time_threshold"
    elif event.loss_trigger == 2:
      trigger = "pto_expired"
    elif event.loss_trigger == 3:
      trigger = "retrans_timer"
    output_arr.append(
      {
        "packet_number": str(event.seq),
        "trigger": trigger,
      }
    )
    if trigger != "":
      qlog["traces"][0]["events"].append(output_arr)
    global final_pkt_evt
    final_pkt_evt[0] = output_arr[0]
		
def print_recvmsg(cpu, data, size):
  event = bpf["recvmsg"].event(data)
  sender = inet_ntop(AF_INET, pack('I', event.saddr))
  #if sender.__contains__("192.168.0.1"):
   # print("tcp recv msg", event.snd_cwnd, event.snd_cwnd_cnt, event.snd_cwnd_clamp, event.prior_cwnd, event.prr_delivered, event.delivered, event.lost, sender, event.len)
  

def print_sendmsg(cpu, data, size):
  event = bpf["sendmsg"].event(data)
  recver = inet_ntop(AF_INET, pack('I', event.daddr))
  #if recver.__contains__("192.168.0.1"):
   # print("tcp send msg", event.snd_cwnd, event.snd_cwnd_cnt, event.snd_cwnd_clamp, event.prior_cwnd, event.prr_delivered, event.delivered, event.lost, recver, event.len)


def print_tcp_transmit(cpu, data, size):
  event = bpf["tcp_transmit"].event(data)
  recver = inet_ntop(AF_INET, pack('I', event.daddr))
  if recver.__contains__("192.168.0.100"):
    time = setTimeInfo(event.timestamp)
    output_arr = []
    output_arr.append("%.6f" % (abs(time) * 1000))
    output_arr.append("transport")
    output_arr.append("packet_sent")
    output_arr.append(
      {
        "packet_type" : "1RTT",
        "header": {
           "packet_number": str(event.seq),
           "len": str(event.len),
         }
      }
    )
    qlog["traces"][0]["events"].append(output_arr)
    global final_pkt_evt
    final_pkt_evt[0] = output_arr[0]
    
def print_tcp_recv(cpu, data, size):
  event = bpf["tcp_rcv"].event(data)
  sender = inet_ntop(AF_INET, pack('I', event.saddr))
  if sender.__contains__("192.168.3.100"):
    time = setTimeInfo(event.timestamp)
    output_arr = []
    output_arr.append("%.6f" % (abs(time) * 1000))
    output_arr.append("transport")
    output_arr.append("packet_received")
    output_arr.append(
      {
        "packet_type" : "1RTT",
        "header": {
           "packet_number": str(event.seq),
           "len": str(event.len),
         }
      }
    )
    qlog["traces"][0]["events"].append(output_arr)
    global final_pkt_evt
    final_pkt_evt[0] = output_arr[0]
  
print("Tracing tcp events ... Hit Ctrl-C to end")

# Bind print functions to ebpf tables 
bpf["cwnd_change"].open_perf_buffer(print_cwnd_change)
bpf["init_event"].open_perf_buffer(print_init_cong_control)
bpf["mark_lost"].open_perf_buffer(print_mark_lost)
bpf["recvmsg"].open_perf_buffer(print_recvmsg)
bpf["sendmsg"].open_perf_buffer(print_sendmsg)
bpf["tcp_transmit"].open_perf_buffer(print_tcp_transmit)
bpf["tcp_rcv"].open_perf_buffer(print_tcp_recv)

if len(sys.argv) == 2:
  outputfile = sys.argv[1]
else:
  outputfile = ti.strftime("%Y-%m-%d-%H-%M", ti.gmtime())
while 1:
  try:
    bpf.perf_buffer_poll()
  except KeyboardInterrupt:
    qlog["traces"][0]["events"].append(final_pkt_evt)
    with open('/logs/' + outputfile + '.qlog', 'w') as f:
      f.write(json.dumps(qlog))
    exit()
