#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "qlog.h"

#define MAX_EXTENSIONS 10

static int  log_file = -1;
static char *qlog_gettime(char *time_str);
static int qlog_open_log_file(const char *vantagepoint);
static  double gettime_ms(void);
static  double start_time;
static int start = 0;
static unsigned int tx_extensions[MAX_EXTENSIONS];
static int nb_tx_extensions;
static unsigned int rx_extensions[MAX_EXTENSIONS];
static int nb_rx_extensions;

static char *qlog_gettime(char *time_str);

static char *qlog_gettime(char *time_str){
  time_t current_time = time(NULL);
  int i;
  char *current_time_str = ctime(&current_time);
  for(i = 0; i < strlen(current_time_str)-1; i++)
    time_str[i] =((*(current_time_str+i)==' ') || (*(current_time_str+i)==':') )?'_':*(current_time_str+i);
  time_str[i] = '\0';
  return time_str;
}

static int qlog_open_log_file(const char *vantagepoint){
  char *path = malloc(43*sizeof(char));
  char *date =  malloc(31*sizeof(char));
  start_time = gettime_ms();
  date = qlog_gettime(date);
  *(date+31) = '\0';
  snprintf(path, 43, "/tmp/%s%s%s", date, vantagepoint, ".qlog");
  int fd = open(path, O_CREAT | O_WRONLY ,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
  if(fd < 0){
    fprintf(stderr, "opening file (%d) (%d) (%s)", fd, errno, path);
  }
  
  return fd;
}

int qlog_init_log(int is_server){
  if(log_file==-1){
    char * vantage_point = is_server?"server":"client";
    int fd = qlog_open_log_file(vantage_point);
    if(fd < 0){
      fprintf(stderr, "Unable to create qlog_file ret (%d)  errno (%d)", fd, errno);
      return fd;
    }
    log_file = fd;  
    size_t writen_bytes = 0;
    writen_bytes = dprintf(log_file, "{"
                    "  \"qlog_version\": \"draft-01\","
                    "  \"traces\": ["
                    "   {"
                    "     \"common_fields\" : { "
                    "        \"reference_time\": \"%.6f\"},"
                    "        \"configuration\": {\"time_units\": \"ms\" },"
                    "     \"event_fields\" : [\"relative_time\", \"category\", \"event_type\", \"data\"],\n"
                    "     \"events\":[", start_time/1000 );
    return writen_bytes;
  }
  fprintf(stderr, "qlog_file already exist\n");
  return 0;
}

int qlog_close_log(int is_server){
  size_t writen_bytes = 0;
  fprintf(stderr, "closing logfile (%d)\n", log_file);
  writen_bytes = dprintf(log_file, "], \"vantage_point\": {\"name\": \"tcpls\", \"type\": \"%s\"}}]}", is_server?"server":"client");
  close(log_file);
  return writen_bytes;
}

int qlog_transport_log(const qlog_dir_evt evt_dir, uint32_t mpseq,
  size_t record_size, qlog_record_evt evt, uint8_t ttype, uint32_t seq, uint32_t streamid){
  static const char * const evt_str[] = {
    [data_record] = "data_record",
    [control_record] = "control_record"
  };
  
  static const char * const evt_dir_str[] = {
    [tx] = "packet_sent",
    [rx] = "packet_received",
  };
  static const char * const ttype_str[] = {
    [none] = "",
    [control_varlen_begin] = "CONTROL_VARLEN_BEGIN",
    [bpf_cc] = "BPF_CC",
    [connid] = "CONNID",
    [cookie] = "COOKIE",
    [data_ack] = "DATA_ACK",
    [failover] = "FAILOVER",
    [failover_end] = "FAILOVER_END",
    [mpjoin] = "MPJOIN",
    [multihoming_v6] = "MULTIHOMING_v6",
    [multihoming_v4] = "MULTIHOMING_v4",
    [user_timeout] = "USER_TIMEOUT",
    [stream_attach] = "STREAM_ATTACH",
    [stream_close] = "STREAM_CLOSE",
    [stream_close_ack] = "STREAM_CLOSE_ACK",
    [transport_new] = "TRANSPORT_NEW"
  };
  double delta_time = (gettime_ms() - start_time)/1000;
  start ? dprintf(log_file,
            ",[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_mpath_seq\" : \"%u\" , \"record_true_type\": \"%u\", \"record_size\":\"%lu\" }, \"frames\": [{\"frame_type\":\"stream\",\"id\": \"%u\"}, {\"frame_type\":\"%s\", \"id\":\"%u\"}]}", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, mpseq, ttype, record_size, streamid, ttype_str[ttype], ttype) : dprintf(log_file,
            "[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_mpath_seq\" : \"%u\" , \"record_true_type\": \"%u\", \"record_size\":\"%lu\" }, \"frames\": [{\"frame_type\":\"stream\",\"id\": \"%u\"}, {\"frame_type\":\"%s\", \"id\":\"%u\"}]}", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, mpseq, ttype, record_size, streamid, ttype_str[ttype], ttype);
  dprintf(log_file, "]") ;
  start = 1;
  return 0;
}


static double gettime_ms(void){
  struct timeval tv1;
  gettimeofday(&tv1, NULL);
  return (tv1.tv_sec * 1000000 + tv1.tv_usec);
}

int qlog_handshake_log(const qlog_dir_evt evt_dir, qlog_record_evt evt, qlog_handshake_evt hevt, uint32_t seq, size_t msg_size){

  static const char * const evt_str[] = {
    [handshake_record] = "handshake_record"
  };
  
  static const char * const evt_dir_str[] = {
    [tx] = "packet_sent",
    [rx] = "packet_received"
  };
  
  static const char * const evt_handshake_str[] = {
    [client_hello] = "client_hello",
    [server_hello] = "server_hello",
    [encrypted_extensions] = "encrypted_extensions",
    [certificate] = "certificate",
    [end_of_early_data] = "end_of_early_data",
    [certificate_verify] = "certificate_verify",
    [finished] = "finished",
    [key_update] = "key_update",
    [certificate_request] = "certificate_request",
    [compressed_certificate] = "compressed_certificate",
    [new_session_ticket] = "new_session_ticket"
  };
  
  double delta_time = (gettime_ms() - start_time)/1000;
  start ? dprintf(log_file,
            ",[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_true_type\": \"%u\", \"msg_size\":\"%lu\" }, \"frames\": [{\"frame_type\":\"%s\", \"id\":\"%u\"}]}", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, hevt, msg_size, evt_handshake_str[hevt], hevt) : dprintf(log_file,
            "[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_true_type\": \"%u\", \"msg_size\":\"%lu\" }, \"frames\": [{\"frame_type\":\"%s\", \"id\":\"%u\"}]}", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, hevt, msg_size, evt_handshake_str[hevt], hevt);
  dprintf(log_file, "]") ;
  start = 1;
  return 0;
}

int qlog_encryptedextensions_log(const qlog_dir_evt evt_dir, qlog_record_evt evt, qlog_handshake_evt hevt, uint32_t seq, size_t msg_size){
  int i ;
   static const char * const evt_str[] = {
    [handshake_record] = "handshake_record"
  };
  
  static const char * const evt_dir_str[] = {
    [tx] = "packet_sent",
    [rx] = "packet_received"
  };
  
  static const char * const extensions_str[] = {
    [encrypted_server_name] = "server_name",
    [server_name] = "server_name",
    [alpn] = "alpn",
    [encrypted_connid] = "connid",
    [encrypted_cookie] = "cookie",
    [encrypted_tcp_options_usertimeout] = "tcp_options_usertimeout",
    [encrypted_multihoming_v4] = "multihoming_v4",
    [encrypted_multihoming_v6] = "multihoming_v6"
  };
  
  double delta_time = (gettime_ms() - start_time)/1000;
  start ? dprintf(log_file,
            ",[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_true_type\": \"%u\", \"msg_size\":\"%lu\" }, \"frames\": [", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, hevt, msg_size) : dprintf(log_file,
            "[\"%.6f\", \"transport\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_number\" : \"%u\", \"record_true_type\": \"%u\", \"msg_size\":\"%lu\" }, \"frames\": [", delta_time,
            evt_dir_str[evt_dir], evt_str[evt], seq, hevt, msg_size);
            
  int n = (evt_dir == rx) ? nb_rx_extensions : nb_tx_extensions;
  for(i = 0; i < n; i++){
    if(i!=(n-1))
      dprintf(log_file, "{\"frame_type\":\"%s\", \"id\":\"%u\"},", (evt_dir == rx) ? extensions_str[rx_extensions[i]] : extensions_str[tx_extensions[i]] , (evt_dir == rx) ? rx_extensions[i] : tx_extensions[i]);
    else 
      dprintf(log_file, "{\"frame_type\":\"%s\", \"id\":\"%u\"}", (evt_dir == rx) ? extensions_str[rx_extensions[i]] : extensions_str[tx_extensions[i]] , (evt_dir == rx) ? rx_extensions[i] : tx_extensions[i]);
  }
  dprintf(log_file, "]}]") ;
  return 0;
}

int qlog_encryptedextensions_init(const qlog_dir_evt evt_dir){
   if(evt_dir == rx)
      nb_rx_extensions = 0;
   else
      nb_tx_extensions = 0;
  return 0;
}

int qlog_encryptedextensions_addextension(const qlog_dir_evt evt_dir, qlog_extensions_evt evt){
  if(evt_dir == rx)
      rx_extensions[nb_rx_extensions++] = evt;
   else
      tx_extensions[nb_tx_extensions++] = evt;
  return 0;
}
