#ifndef picotypes_h
#define picotypes_h
#include <stdint.h>
#include <event2/event.h>
/** Main common taypes */

typedef struct st_tcpls_options_t tcpls_options_t;

typedef uint32_t streamid_t;
typedef struct st_ptls_t ptls_t;
typedef struct st_tcpls_t tcpls_t;
typedef struct st_ptls_context_t ptls_context_t;
typedef struct st_ptls_iovec_t ptls_iovec_t;
typedef struct st_ptls_buffer_t ptls_buffer_t;
typedef struct st_ptls_aead_context_t ptls_aead_context_t;
typedef struct st_tcpls_record_fifo_t tcpls_record_fifo_t;
typedef struct st_list_t list_t;
typedef struct st_ptls_handshake_properties_t ptls_handshake_properties_t;
typedef struct st_tcpls_buffer tcpls_buffer_t;
typedef struct st_tcpls_event_base tcpls_event_base_t;
typedef void (*tcpls_do_accept_cb)(int socket, struct sockaddr* addr, int
    socklen, void *ptr);
#endif
