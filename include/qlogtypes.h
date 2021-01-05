#ifndef qlogtypes_h
#define qlogtypes_h

typedef enum { 
  data_record, 
  control_record, handshake_record
} qlog_record_evt ;

typedef enum{
  tx,
  rx
}qlog_dir_evt;

typedef enum{
  none = 1,
  control_varlen_begin,
  bpf_cc,
  connid,
  cookie,
  data_ack,
  failover,
  failover_end,
  mpjoin,
  multihoming_v6,
  multihoming_v4,
  user_timeout,
  stream_attach,
  stream_close,
  stream_close_ack,
  transport_new
}qlog_tcpls_evt;

typedef enum { 
  client_hello, server_hello, 
  encrypted_extensions, certificate, end_of_early_data, certificate_verify, finished, 
  key_update, certificate_request, compressed_certificate, new_session_ticket
}qlog_handshake_evt;

typedef enum { 
  client_hello_seq, server_hello_seq, 
  encrypted_extensions_seq, certificate_seq, end_of_early_data_seq, certificate_verify_seq, finished_seq, 
  key_update_seq, certificate_request_seq, compressed_certificate_seq, new_session_ticket_seq
}qlog_handshake_seq;

typedef enum { 
  encrypted_server_name, server_name, alpn, early_data, encrypted_connid, 
  encrypted_cookie, encrypted_tcp_options_usertimeout, encrypted_multihoming_v4,
  encrypted_multihoming_v6
}qlog_extensions_evt;

#endif
