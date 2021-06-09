#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"
#include "picotls.h"
#include "containers.h"
#include "heap.h"
#include <netinet/in.h>
#define NBR_SUPPORTED_TCPLS_OPTIONS 5
#define VARSIZE_OPTION_MAX_CHUNK_SIZE 4*16384 /* should be able to hold 4 records before needing to be extended */

#define TCPLS_SIGNAL_SIZE 12
#define STREAM_SENDER_NEW_STREAM_SIZE 4
#define STREAM_CLOSE_SIZE 4

#define TCPLS_OK 0
#define TCPLS_HOLD_DATA_TO_READ 1
#define TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ 2
#define TCPLS_HOLD_DATA_TO_SEND 3

#define COOKIE_LEN 16
#define CONNID_LEN 16

#define SENDING_ACKS_RECORDS_WINDOW 16

// MAX_ENCRYPTED_RECORD_SIZE * 15
#define SENDING_ACKS_BYTES_WINDOW 249600

#if defined(PTCPLS_DEBUG) && PTCPLS_DEBUG
#define PTCPLS_DEBUGF(...) fprintf(stderr, __VA_ARGS__)
#else
#define PTCPLS_DEBUGF(...)
#endif


/** TCPLS messages we would support in the TLS context */
typedef enum tcpls_enum_t {
  NONE, // this one is just for plain data
  CONTROL_VARLEN_BEGIN,
  BPF_CC,
  CONNID,
  COOKIE,
  DATA_ACK,
  FAILOVER,
  FAILOVER_END,
  MPJOIN,
  MULTIHOMING_v6,
  MULTIHOMING_v4,
  USER_TIMEOUT,
  STREAM_ATTACH,
  STREAM_CLOSE,
  STREAM_CLOSE_ACK,
  TRANSPORT_NEW,
  TRANSPORT_UPDATE,
  /* since it is a protocol message (we do memcpy of this thing), make sure the
   * enum is compiled into a 32 bits representation */
  tcpls_enum_sentinel = 4294967295UL
} tcpls_enum_t;

typedef enum tcpls_event_t {
  CONN_CLOSED,
  CONN_FAILED,
  CONN_OPENED,
  STREAM_CLOSED,
  STREAM_OPENED,
  STREAM_NETWORK_FAILURE,
  STREAM_NETWORK_RECOVERED,
  /* tells the app that we may have an address to add */
  ADD_ADDR,
  /* tells the app that we added an address! */
  ADDED_ADDR,
  REMOVE_ADDR
} tcpls_event_t;

typedef enum tcpls_tcp_state_t {
  CLOSED,
  FAILED, /*This con encountered a network failure */
  CONNECTING,
  CONNECTED,
  JOINED
} tcpls_tcp_state_t;

struct st_tcpls_options_t {
  tcpls_enum_t type;
  uint8_t setlocal; /** Whether or not we also apply the option locally */
  uint8_t settopeer; /** Whether or not this option might be sent to the peer */
  uint8_t is_varlen; /** Tell whether this option is of variable length */
  ptls_iovec_t *data;
};

typedef struct st_tcpls_v4_addr_t {
  struct sockaddr_in addr;
  unsigned is_primary : 1; /* whether this is our primary address */
  unsigned is_ours : 1;  /* is this our address? */
  struct st_tcpls_v4_addr_t *next;
} tcpls_v4_addr_t;

typedef struct st_tcpls_v6_addr_t {
  struct sockaddr_in6 addr;
  unsigned is_primary : 1;
  unsigned is_ours : 1;
  struct st_tcpls_v6_addr_t *next;
} tcpls_v6_addr_t;

typedef struct st_connect_info_t {
  tcpls_tcp_state_t state; /* Connection state */
  int socket;
  /**
   * Fragmentation buffer for TCPLS control records received over this
   * connection
   **/
  ptls_buffer_t *buffrag;
  /** nbr bytes received since the last ackknowledgment sent */
  uint32_t nbr_bytes_received;
  /** nbr records received on this con since the last ack sent */
  uint32_t nbr_records_received;
  /** total number of DATA bytes received over this con */
  uint64_t tot_data_bytes_received;
  /** total number of CONTROL bytess received over this con */
  uint64_t tot_control_bytes_received;
  /** Id given for this connection */
  uint32_t this_transportid;
  /** Id of the peer fort this connection */
  uint32_t peer_transportid;
  /** Is this connection primary? Primary means the default one */
  unsigned is_primary : 1;
  /* con_to_failover received a FAILOVER message with a stream linked to this
   * con.
   * If we have data in our send_queue we need to send them over con and then destroy the
   * connection 
   */
  uint32_t transportid_to_failover;

  /** RTT of this connection, computed by the client and ?eventually given to the
   * server TODO*/
  struct timeval connect_time;
  /** Only one is used */
  tcpls_v4_addr_t *src;
  tcpls_v6_addr_t *src6;
  /** only one is used */
  tcpls_v4_addr_t *dest;
  tcpls_v6_addr_t *dest6;

} connect_info_t;

typedef struct st_tcpls_stream {
  
  streamid_t streamid;
  /** when this stream should first send an attach event before
   * sending any packet */
  unsigned need_sending_attach_event  : 1;
  /**
   * As soon as we have sent a stream attach event to the other peer, this
   * stream is usable
   */
  unsigned stream_usable : 1;

  /**
   * the stream should be cleaned up the next time tcpls_send is called
   */
  unsigned marked_for_close : 1;

  /**
   * Whether we still have to initialize the aead context for this stream.
   * That may happen if this stream is created before the handshake took place.
   */
  unsigned aead_initialized : 1;
  /** Note: The following contexts use the same key; but a different counter and
   * IV
   */
  /* Context for encryption */
  ptls_aead_context_t *aead_enc;
  /* Context for decryption */
  ptls_aead_context_t *aead_dec;
  /* Used for retaining records that have not been acknowledged yet */
  tcpls_record_fifo_t *send_queue;
  /* The last sequence number whom which we decrypted and processed some data
   * from that stream */
  uint32_t last_seq_received;
  /* Number of records received on this stream since the last acknowledgement sent */
  uint32_t nbr_records_since_last_ack;
  /* Number of bytes received on this stream since the last acknowledgement sent */
  uint32_t nbr_bytes_since_last_ack;

  /* Per stream sending buffer */
  ptls_buffer_t *sendbuf;
  /** for sending buffer */
  int send_start;
  /** end position of the stream control event message in the current sending
   * buffer*/
  int send_stream_attach_in_sendbuf_pos;
  /** Attached connection -- must be the index of the connection within
   * tcpls->connect_infos
   **/
  uint32_t transportid;
  /**
   * Origin attached con
   * In case of failover, we mark orcon as the origin con
   * of this stream, before it got moved
   **/
  uint32_t orcon_transportid;
  /*Used when failover is enable -- tell us from which seq number is expected remain in our sending
   *buffer for this stream (last_seq_poped+1 is expected to be the next one in sendbuf if one is)
   *We use this information within a FAILOVER message to tell the peer which number is expected to
   *decrypt correctly */

  /** offset assigned to this stream for the iv derivation */
  uint32_t offset;

  unsigned int failover_end_sent : 1;
  unsigned int failover_end_received : 1;
  uint32_t last_seq_poped;
} tcpls_stream_t;


struct st_tcpls_t {
  ptls_t *tls;
  /* Sending buffer */
  ptls_buffer_t *sendbuf;
  /** If we did not manage to empty sendbuf in one send call */
  int send_start;
  /* Receiving buffer */
  uint8_t *recvbuf;
  int recvbuflen;
  /**
   * Fragmentation buffer for TCPLS -- used when no streams are attached yet
   * */
  ptls_buffer_t *buffrag;
  /* Record buffer for multipath reordering */
  ptls_buffer_t *rec_reordering;
  /* store buf_position_data */
  heap *gap_rec_reordering;
  /* Current gap_size -- i.e., the amount of data we can safefely shift the
   * reordering buffer*/
  uint32_t gap_size;
  /* max_gap size until shift_buffer */
  uint32_t max_gap_size;
  /* gap offset for dataposition */
  uint64_t gap_offset;
  /** A priority queue to handle reording records */
  heap *priority_q;
  /** sending mpseq number */
  uint32_t send_mpseq;
  /** next expected receive seq */
  uint32_t next_expected_mpseq;
  /* Size of a varlen option set when we receive a CONTROL_VARLEN_BEGIN */
  uint32_t varlen_opt_size;
  /**
   * Linked List of address to be used for happy eyeball
   * and for failover
   */
  /** Destination addresses */
  tcpls_v4_addr_t *v4_addr_llist;
  tcpls_v6_addr_t *v6_addr_llist;
  /** Our addresses */
  tcpls_v4_addr_t *ours_v4_addr_llist;
  tcpls_v6_addr_t *ours_v6_addr_llist;
  /**
   * pointer to the Application-created receiving buffer -- Only one may be
   * created at a time
   **/
  tcpls_buffer_t *buffer;

  /**
   *  enable failover; used for rst/drop resistance in case of
   *  network outage .. If multiple connections are available
   *  This is costly since it also enable ACKs at the TCPLS layer, and
   *  bufferization of the data sent
   *  */
  unsigned int enable_failover : 1;
  /**
   * Enable multipath ordering, setting a multipath sequence number in TCPLS data
   * messages, and within control informations that apply for multipathing
   * XXX currently, no options are multipath-capable; Eventually every VARLEN
   * option should become multipath capable.
   *
   * Note; not activating multipath still allow to use multiple paths strictly
   * speaking, but ordering won't be guaranteed between sent received packets
   * within different paths. That's still useful if the application seperate
   * application objects per path.
   */
  unsigned int enable_multipath: 1;
  /** Are we recovering from a network failure? */
  unsigned int failover_recovering : 1;
  /** nbr of FAILOVER_END that we remain to see */
  int nbr_remaining_failover_end;
  /* tells ptls_send on which con we expect to send encrypted bytes*/
  connect_info_t *sending_con;
  /* tells ptls_send on which stream we send encrypted bytes */
  tcpls_stream_t *sending_stream;
  /** carry a list of tcpls_option_t */
  list_t *tcpls_options;
  /** Should contain all streams */
  list_t *streams;
  /** We have stream control event to check */
  unsigned check_stream_attach_sent : 1;
  /** We have stream marked for close; close them after sending the control
   * message  */
  unsigned streams_marked_for_close : 1;
  /** Connection ID used for MPJOIN */
  uint8_t connid[128];
  /** Multihoming Cookie */
  list_t *cookies;
  /** Indicates the position of the current cookie value within the
   * HMAC chain of cookies */
  int cookie_counter;
  /** Contains the state of connected src and dest addresses */
  list_t *connect_infos;
  /** value of the next stream id :) */
  uint32_t next_stream_id;
  /** value of the next transport id */
  uint32_t next_transport_id;
  /** count the number of times we attached a stream from the peer*/
  uint32_t nbr_of_peer_streams_attached;
  /** count the number of streams attached */
  uint32_t nbr_of_our_streams_attached;
  /** nbr of tcp connection */
  uint32_t nbr_tcp_streams;
  /** socket of the primary address - must be update at each primary change*/
  int socket_primary;
  /** remember on which connection we are pulling bytes */
  int transportid_rcv;
  /** remember on which stream we are decrypting -- useful to send back a
   * DATA_ACK with the right stream*/
  streamid_t streamid_rcv;
  /** the very initial socket used for the handshake */
  int initial_socket;

  /**
   * Scheduler callback for the receiver. Can be set by the application to
   * instrument how multiple connections should pull bytes.
   */
  int (*schedule_receive)(tcpls_t *tcpls, fd_set *rset, tcpls_buffer_t *decryptbuf, void *data);

  /**
   * Set to 1 if the other peer also announced it supports Encrypted TCP
   * options
   */
  unsigned tcpls_options_confirmed : 1;
  /* used to initialize buffer size -- should be the aad size*/
  int init_buf_reserve;
};

struct st_ptls_record_t;

/*=====================================API====================================*/

/** API exposed to the application */

void *tcpls_new();

int tcpls_connect(ptls_t *tls, struct sockaddr *src, struct sockaddr *dest,
    struct timeval *timeout);

int tcpls_handshake(ptls_t *tls, ptls_handshake_properties_t *properties);

int tcpls_accept(tcpls_t *tcpls, int socket, uint8_t *cookie, uint32_t transportid);

int tcpls_add_v4(ptls_t *tls, struct sockaddr_in *addr, int is_primary, int
    settopeer, int is_ours);

int tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary, int
    settopeer, int is_ours);

uint32_t tcpls_stream_new(ptls_t *tls, struct sockaddr *src, struct sockaddr *addr);

int tcpls_streams_attach(ptls_t *tls, streamid_t streamid, int sendnow);

int tcpls_stream_close(ptls_t *tls, streamid_t streamid, int sendnow);

/**
 * tcpls_send can be called whether or not tcpls_stream_new has been called before
 * by the application; but it must send a stream_attach record first to attach a
 * stream.
 */

int tcpls_send(ptls_t *tls, streamid_t streamid, const void *input, size_t nbytes);

/**
 * Eventually read bytes and pu them in input -- Make sure the socket is
 * in blocking mode
 */
int tcpls_receive(ptls_t *tls, tcpls_buffer_t *input, struct timeval *tv);

int tcpls_set_user_timeout(tcpls_t *tcpls, int transportid, uint16_t value,
    uint16_t msec_or_sec, uint8_t setlocal, uint8_t settopeer);

int tcpls_set_bpf_scheduler(tcpls_t *tcpls, const uint8_t *bpf_prog_bytecode,
    size_t bytecodelen, int setlocal, int settopeer);

int tcpls_send_tcpoption(tcpls_t *tcpls, int transportid, tcpls_enum_t type, int sendnow);

void tcpls_free(tcpls_t *tcpls);

/*============================================================================*/
/** Internal to picotls */

int tcpls_internal_data_process(tcpls_t *tcpls, connect_info_t *con, int recvret, tcpls_buffer_t *decryptbuf);

int get_tcpls_header_size(tcpls_t *tcpls, uint8_t type, tcpls_enum_t message);

connect_info_t *connection_get(tcpls_t *tcpls, uint32_t transportid);

int is_varlen(tcpls_enum_t message);

int is_handshake_tcpls_message(tcpls_enum_t message);

int is_failover_valid_message(uint8_t type, tcpls_enum_t message);

int handle_tcpls_control(ptls_t *ctx, tcpls_enum_t type,
    const uint8_t *input, size_t len);

int handle_tcpls_control_record(ptls_t *tls, struct st_ptls_record_t *rec);
int handle_tcpls_data_record(ptls_t *tls, struct st_ptls_record_t *rec);

int tcpls_failover_signal(tcpls_t *tcpls, ptls_buffer_t *sendbuf);

void ptls_tcpls_options_free(tcpls_t *tcpls);

#endif
