/**
 * \file picotcpls.c
 *
 * \brief Implement logic for setting, sending, receiving and processing TCP
 * options through the TLS layer, as well as offering a wrapper for the
 * transport protocol and expose only one interface to the application layer
 *
 * This file defines an API exposed to the application
 * <ul>
 *   <li> tcpls_new </li>
 *   <li> tcpls_add_v4 </li>
 *   <li> tcpls_add_v6 </li>
 *   <li> tcpls_connect </li>
 *   <li> tcpls_accept </li>
 *   <li> tcpls_handshake </li>
 *   <li> tcpls_send </li>
 *   <li> tcpls_receive </li>
 *   <li> tcpls_stream_new </li> (Optional)
 *   <li> tcpls_streams_attach </li> (Optional)
 *   <li> tcpls_stream_close </li> (Optional)
 *   <li> tcpls_free </li>
 * </ul>
 *
 * Callbacks can be attached to message events happening within TCPLS. E.g.,
 * upon a new stream attachment, a fonction provided by the application might be
 * called and would be passed information about the particular event.
 *
 * We also offer an API to set localy and/or to the
 * peer some TCP options. We currently support the following options:
 *
 * <ul>
 *    <li> User Timeout RFC5482 </li>
 *    <li> Failover </li>
 *    <li> BPF injection of a Congestion Control scheme (kernel >= 5.6)  </li>
 * </ul>
 *
 * To set up a TCP option, the application layer should first turns on
 * ctx->support_tcpls_options = 1; which will advertise to the peer the
 * capability of handling TCPLS. Then, we may set locally or remotly TCP options
 * by doing:
 *
 * ptls_set_[OPTION]
 * and then
 *
 * ptls_send_tcpotion(...)
 *
 */
 
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <log.h>

#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include "picotypes.h"
#include "containers.h"
#include "picotls.h"
#include "picotcpls.h"
/** Forward declarations */
static int tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer);
static int is_varlen(tcpls_enum_t type);
static int setlocal_usertimeout(ptls_t *ptls, int val);
static int setlocal_bpf_cc(ptls_t *ptls, const uint8_t *bpf_prog, size_t proglen);
static void _set_primary(tcpls_t *tcpls);
static tcpls_stream_t *stream_new(ptls_t *tcpls, streamid_t streamid,
    connect_info_t *con, int is_ours);
static void stream_free(tcpls_stream_t *stream);
static int cmp_times(struct timeval *t1, struct timeval *t2);
static int stream_send_control_message(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_aead_context_t *enc,
    const void *inputinfo, tcpls_enum_t message, uint32_t message_len);
static connect_info_t *get_con_info_from_socket(tcpls_t *tcpls, int socket);
static connect_info_t *get_best_con(tcpls_t *tcpls);
static int get_con_info_from_addrs(tcpls_t *tcpls, tcpls_v4_addr_t *src,
    tcpls_v4_addr_t *dest, tcpls_v6_addr_t *src6, tcpls_v6_addr_t *dest6,
    connect_info_t **coninfo);
static tcpls_v4_addr_t *get_addr_from_sockaddr(tcpls_v4_addr_t *llist, struct sockaddr_in *addr);
static tcpls_v6_addr_t *get_addr6_from_sockaddr(tcpls_v6_addr_t *llist, struct sockaddr_in6 *addr);
static connect_info_t *get_primary_con_info(tcpls_t *tcpls);
static int count_streams_from_socket(tcpls_t *tcpls, int socket);
static tcpls_stream_t *stream_get(tcpls_t *tcpls, streamid_t streamid);
static tcpls_stream_t *stream_helper_new(tcpls_t *tcpls, connect_info_t *con);
static void check_stream_attach_have_been_sent(tcpls_t *tcpls, int consumed);
static int new_stream_derive_aead_context(ptls_t *tls, tcpls_stream_t *stream, int is_ours);
static int handle_connect(tcpls_t *tcpls, tcpls_v4_addr_t *src, tcpls_v4_addr_t
    *dest, tcpls_v6_addr_t *src6, tcpls_v6_addr_t *dest6, unsigned short sa_family,
    int *nfds, connect_info_t *coninfo, int socket);
static int multipath_merge_buffers(tcpls_t *tcpls, ptls_buffer_t *decryptbuf);
static int cmp_mpseq(void *mpseq1, void *mpseq2);
static int check_con_has_connected(tcpls_t *tcpls, connect_info_t *con, int *res);
static void compute_client_rtt(connect_info_t *con, struct timeval *timeout,
    struct timeval *t_initial, struct timeval *t_previous);
static void connection_close(tcpls_t *tcpls, connect_info_t *con);
/**
 * Create a new TCPLS object
 */
void *tcpls_new(void *ctx, int is_server) {
  ptls_t *tls;
  ptls_context_t *ptls_ctx = (ptls_context_t *) ctx;
  tcpls_t *tcpls  = malloc(sizeof(*tcpls));
  if (tcpls == NULL)
    return NULL;
  memset(tcpls, 0, sizeof(*tcpls));
  tcpls->cookies = new_list(COOKIE_LEN, 4);
  if (is_server) {
    tls = ptls_server_new(ptls_ctx);
    tcpls->next_stream_id = 2147483649;  // 2**31 +1
    /** Generate connid and cookie */
    ptls_ctx->random_bytes(tcpls->connid, CONNID_LEN);
    uint8_t rand_cookies[COOKIE_LEN];
    for (int i = 0; i < 4; i++) {
      ptls_ctx->random_bytes(rand_cookies, COOKIE_LEN);
      list_add(tcpls->cookies, rand_cookies);
    }
  }
  else {
    tls = ptls_client_new(ptls_ctx);
    tcpls->next_stream_id = 1;
  }
  // init tcpls stuffs
  tcpls->sendbuf = malloc(sizeof(*tcpls->sendbuf));
  tcpls->recvbuf = malloc(sizeof(*tcpls->recvbuf));
  tcpls->rec_reordering = malloc(sizeof(*tcpls->rec_reordering));
  tcpls->tls = tls;
  ptls_buffer_init(tcpls->sendbuf, "", 0);
  ptls_buffer_init(tcpls->recvbuf, "", 0);
  ptls_buffer_init(tcpls->rec_reordering, "", 0);
  /** From the heap API, a NULL cmp function compares keys as integers, which is
   * what we need */
  tcpls->priority_q = malloc(sizeof(*tcpls->priority_q));
  heap_create(tcpls->priority_q, 0, cmp_mpseq);
  tcpls->tcpls_options = new_list(sizeof(tcpls_options_t), NBR_SUPPORTED_TCPLS_OPTIONS);
  tcpls->streams = new_list(sizeof(tcpls_stream_t), 3);
  tcpls->connect_infos = new_list(sizeof(connect_info_t), 2);
  tls->tcpls = tcpls;
  return tcpls;
}


int static add_v4_to_options(tcpls_t *tcpls, uint8_t n) {
  /** Contains the number of IPs in [0], and then the 32 bits of IPs */
  uint8_t *addresses = malloc(sizeof(struct in_addr)+1);
  if (!addresses)
    return PTLS_ERROR_NO_MEMORY;
  tcpls_v4_addr_t *current = tcpls->ours_v4_addr_llist;
  if (!current) {
    return -1;
  }
  int i = 1;
  while (current && i < sizeof(struct in_addr)+1) {
    memcpy(&addresses[i], &current->addr.sin_addr, sizeof(struct in_addr));
    i+=sizeof(struct in_addr);
    current = current->next;
  }
  /** TODO, check what bit ordering to do here */
  addresses[0] = n;
  return tcpls_init_context(tcpls->tls, addresses, sizeof(struct in_addr)+1, MULTIHOMING_v4, 0, 1);
}

int static add_v6_to_options(tcpls_t *tcpls, uint8_t n) {
  uint8_t *addresses = malloc(sizeof(struct in6_addr)+1);
  if (!addresses)
    return PTLS_ERROR_NO_MEMORY;
  tcpls_v6_addr_t *current = tcpls->ours_v6_addr_llist;
  if (!current)
    return -1;
  int i = 1;
  while (current && i < sizeof(struct in6_addr)+1) {
    memcpy(&addresses[i], &current->addr.sin6_addr.s6_addr, sizeof(struct in6_addr));
    i+=sizeof(struct in6_addr);
    current = current->next;
  }
  addresses[0] = n;
  return tcpls_init_context(tcpls->tls, addresses, sizeof(struct in6_addr),
      MULTIHOMING_v6, 0, 1);
}

/**
 * Copy Sockaddr_in into our structures. If is_primary is set, flip that bit
 * from any other v4 address if set.
 *
 * if settopeer is enabled, it means that this address is actually ours and meant to
 * be sent to the peer
 *
 * if settopeer is 0, then this address is the peer's one
 */

int tcpls_add_v4(ptls_t *tls, struct sockaddr_in *addr, int is_primary, int
    settopeer, int is_ours) {
  tcpls_t *tcpls = tls->tcpls;
  /* enable failover */
  if (!settopeer)
    tls->ctx->failover = 1;
  tcpls_v4_addr_t *new_v4 = malloc(sizeof(tcpls_v4_addr_t));
  if (new_v4 == NULL)
    return PTLS_ERROR_NO_MEMORY;
  memset(new_v4, 0, sizeof(*new_v4));
  new_v4->is_primary = is_primary;
  memcpy(&new_v4->addr, addr, sizeof(*addr));
  new_v4->next = NULL;
  new_v4->is_ours = is_ours;
  tcpls_v4_addr_t *current;
  if (is_ours)
    current = tcpls->ours_v4_addr_llist;
  else
    current = tcpls->v4_addr_llist;
  if (!current) {
    if (is_ours)
      tcpls->ours_v4_addr_llist = new_v4;
    else
      tcpls->v4_addr_llist = new_v4;
    if (settopeer)
      return add_v4_to_options(tcpls, 1);
    return 0;
  }
  int n = 0;
  while (current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    /** we already added this address */
    if (!memcmp(&current->addr, addr, sizeof(*addr))) {
      free(new_v4);
      return TCPLS_ADDR_EXIST;
    }
    current = current->next;
    n++;
  }
  /** look into the last item */
  if (!memcmp(&current->addr, addr, sizeof(*addr))) {
    free(new_v4);
    return -1;
  }
  current->next = new_v4;
  if (settopeer)
    return add_v4_to_options(tcpls, n);
  return 0;
}

int tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary, int
    settopeer, int is_ours) {
  tcpls_t *tcpls = tls->tcpls;
  tcpls_v6_addr_t *new_v6 = malloc(sizeof(*new_v6));
  if (new_v6 == NULL)
    return PTLS_ERROR_NO_MEMORY;
  memset(new_v6, 0, sizeof(*new_v6));
  new_v6->is_primary = is_primary;
  memcpy(&new_v6->addr, addr, sizeof(*addr));
  new_v6->next = NULL;
  new_v6->is_ours = is_ours;
  tcpls_v6_addr_t *current;
  if (is_ours)
    current = tcpls->ours_v6_addr_llist;
  else
    current = tcpls->v6_addr_llist;
  if (!current) {
    if (is_ours)
      tcpls->ours_v6_addr_llist = new_v6;
    else
      tcpls->v6_addr_llist = new_v6;
    if (settopeer)
      return add_v6_to_options(tcpls, 1);
    return 0;
  }
  int n = 0;
  while(current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    if (!memcmp(&current->addr, addr, sizeof(*addr))) {
      free(new_v6);
      return -1;
    }
    current = current->next;
    n++;
  }
  if (!memcmp(&current->addr, addr, sizeof(*addr))) {
    free(new_v6);
    return -1;
  }
  current->next = new_v6;
  if (settopeer)
    return add_v6_to_options(tcpls, n);
  return 0;
}
/** For connect-by-name sparing 2-RTT logic! Much much further work */
int tcpls_add_domain(ptls_t *tls, char* domain) {
  return 0;
}

/**
 * Makes TCP connections to registered IPs that are in CLOSED state.
 *
 * Returns -1 upon error
 *         -2 upon timeout experiration without any addresses connected
 *         1 if the timeout fired but some address(es) connected
 *         0 if all addresses connected
 */

int tcpls_connect(ptls_t *tls, struct sockaddr *src, struct sockaddr *dest,
    struct timeval *timeout, int socket) {
  tcpls_t *tcpls = tls->tcpls;
  int maxfds = 0;
  int nfds = 0;
  int ret;
  fd_set wset;
  FD_ZERO(&wset);
  connect_info_t coninfo;
  memset(&coninfo, 0, sizeof(connect_info_t));
  if (!src && !dest) {
    // FULL MESH CONNECT
    tcpls_v4_addr_t *current_v4 = tcpls->v4_addr_llist;
    tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
    while (current_v4 || current_v6) {
      tcpls_v4_addr_t *ours_current_v4 = tcpls->ours_v4_addr_llist;
      tcpls_v6_addr_t *ours_current_v6 = tcpls->ours_v6_addr_llist;
      do {
        if (current_v4) {
          if (handle_connect(tcpls, ours_current_v4, current_v4, NULL, NULL, AF_INET, &nfds, &coninfo, socket) < 0) {
            return -1;
          }
        }
        if (current_v6) {
          if(handle_connect(tcpls, NULL, NULL, ours_current_v6, current_v6, AF_INET6, &nfds, &coninfo, socket) < 0) {
            return -1;
          }
        }
        /** move forward */    
        if (ours_current_v4)
          ours_current_v4 = ours_current_v4->next;
        if (ours_current_v6)
          ours_current_v6 = ours_current_v6->next;
      } while (ours_current_v4 || ours_current_v6);
      if (current_v4)
          current_v4 = current_v4->next;
      if (current_v6)
          current_v6 = current_v6->next;
    }
  }
  else if (src && !dest) {
    /** Connect to all destination from one particular src addr */
    if (src->sa_family == AF_INET) {
      tcpls_v4_addr_t *current_v4 = tcpls->v4_addr_llist;
      tcpls_v4_addr_t* ours_v4 = get_addr_from_sockaddr(tcpls->ours_v4_addr_llist, (struct sockaddr_in *)src);
      /** src should have been added with tcpls_add_v4 first */
      if (!ours_v4)
        return -1;
      while (current_v4) {
        if (handle_connect(tcpls, ours_v4, current_v4, NULL, NULL, AF_INET, &nfds, &coninfo, socket) < 0) {
          return -1;
        }
        current_v4 = current_v4->next;
      }
    }
    else if (src->sa_family == AF_INET6) {
      tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
      tcpls_v6_addr_t *ours_v6 = get_addr6_from_sockaddr(tcpls->ours_v6_addr_llist, (struct sockaddr_in6 *) src);
      if (!ours_v6)
        return -1;
      while (current_v6) {
        if (handle_connect(tcpls, NULL, NULL, ours_v6, current_v6, AF_INET6, &nfds, &coninfo, socket) < 0) {
          return -1;
        }
        current_v6 = current_v6->next;
      }
    }
  }
  else if (src && dest) {
    /** Connect to a provided src and addr */
    if (src->sa_family == AF_INET && dest->sa_family == AF_INET) {
      tcpls_v4_addr_t *our_addr = get_addr_from_sockaddr(tcpls->ours_v4_addr_llist, (struct sockaddr_in *) src);
      tcpls_v4_addr_t *dest_addr = get_addr_from_sockaddr(tcpls->v4_addr_llist, (struct sockaddr_in *) dest);
      if (!our_addr || !dest_addr)
        return -1;
      if (handle_connect(tcpls, our_addr, dest_addr, NULL, NULL, AF_INET, &nfds, &coninfo, socket) < 0) {
        return -1;
      }
    }
    else if (src->sa_family == AF_INET6 && dest->sa_family == AF_INET6) {
      tcpls_v6_addr_t *our_addr = get_addr6_from_sockaddr(tcpls->ours_v6_addr_llist, (struct sockaddr_in6 *) src);
      tcpls_v6_addr_t *dest_addr = get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct sockaddr_in6 *) dest);
      if (!our_addr || !dest_addr)
        return -1;
      if (handle_connect(tcpls, NULL, NULL, our_addr, dest_addr, AF_INET6, &nfds, &coninfo, socket) < 0) {
        return -1;
      }
    }
  }
  else if (!src && dest) {
    /** Connect to a provided dest from default src */
    if (dest->sa_family == AF_INET) {
      tcpls_v4_addr_t *dest_addr = get_addr_from_sockaddr(tcpls->v4_addr_llist, (struct sockaddr_in *)dest);
      if (!dest_addr)
        return -1;
      if (handle_connect(tcpls, NULL, dest_addr, NULL, NULL, AF_INET, &nfds, &coninfo, socket) < 0) {
        return -1;
      }
    }
    else {
      tcpls_v6_addr_t *dest_addr = get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct sockaddr_in6 *) dest);
      if (!dest_addr)
        return -1;
      if (handle_connect(tcpls, NULL, NULL, NULL, dest_addr, AF_INET6, &nfds, &coninfo, socket) < 0) {
        return -1;
      }
    }
  }
  /* wait until all connected or the timeout fired */
  int remaining_nfds = nfds;
  struct timeval t_initial, t_previous;
  gettimeofday(&t_initial, NULL);
  memcpy(&t_previous, &t_initial, sizeof(t_previous));
  tcpls->nbr_tcp_streams = nfds;
  connect_info_t *con;
  int nbr_errors = 0;
  while (remaining_nfds) {
    int result = 0;
    FD_ZERO(&wset);
    for (int i = 0; i < tcpls->connect_infos->size; i++) {
      con = list_get(tcpls->connect_infos, i);
      if (con->state == CONNECTING) {
        FD_SET(con->socket, &wset);
        if (con->socket > maxfds)
          maxfds = con->socket;
      }
    }
    if ((ret = select(maxfds+1, NULL, &wset, NULL, timeout)) < 0) {
      return -1;
    }
    else if (!ret) {
      /* the timeout fired! */
      if (remaining_nfds == nfds) {
        /* None of the addresses connected */
        return -2;
      }
      return 1;
    }
    else {
      /** Check first for connection result! */
      for (int i = 0; i < tcpls->connect_infos->size; i++) {
        con = list_get(tcpls->connect_infos, i);
        if (con->state == CONNECTING && FD_ISSET(con->socket, &wset)) {
          if (check_con_has_connected(tcpls, con, &result) < 0) {
            connection_close(tcpls, con);
            break;
          }
          if (result != 0) {
            FD_CLR(con->socket, &wset);
            connection_close(tcpls, con);
            nbr_errors++;
            break;
          }
          /** we connected! */
          else {
            struct timeval timeout = {.tv_sec = 100, .tv_usec = 0};
            compute_client_rtt(con, &timeout, &t_initial, &t_previous);
            int flags = fcntl(con->socket, F_GETFL);
            flags &= ~O_NONBLOCK;
            fcntl(con->socket, F_SETFL, flags);
          }
        }
      }
      remaining_nfds-=ret;
    }
  }
  if (nbr_errors == nfds)
    return -1;
  _set_primary(tcpls);
  return 0;
}

/**
 * Performs a TLS handshake upon the primary connection. If this handshake is
 * properties tu support multihoming connections. Note that, server side, then
 * server-side, the server must provide a callback function in the handshake
 * the handshake message might either be the start of a new hanshake, or a
 * JOIN handshake.
 *
 * Client-side: the client must provide handshake properties for MPJOIN
 * handshake
 */

// TODO move socket in handshake properties

int tcpls_handshake(ptls_t *tls, ptls_handshake_properties_t *properties) {
  tcpls_t *tcpls = tls->tcpls;
  ssize_t rret = 1;
  connect_info_t *con = NULL;
  struct timeval t_initial, t_previous;
  if (!tcpls)
    return -1;
  int sock = 0;
  /** O-RTT handshakes? */
  if (properties && properties->client.zero_rtt) {
    /* tells from ptls_handshake_properties on which address to connect to */
    if (!properties->client.dest)
      return -1;
     
    int ret;
    if (properties->client.dest->ss_family == AF_INET)
      ret = get_con_info_from_addrs(tcpls,
          get_addr_from_sockaddr(tcpls->ours_v4_addr_llist, (struct sockaddr_in*) properties->client.src),
          get_addr_from_sockaddr(tcpls->v4_addr_llist, (struct sockaddr_in*) properties->client.dest),
          NULL, NULL, &con);
    else
      ret = get_con_info_from_addrs(tcpls, NULL, NULL,
        get_addr6_from_sockaddr(tcpls->ours_v6_addr_llist, (struct sockaddr_in6*) properties->client.src),
        get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct sockaddr_in6*) properties->client.dest),
        &con);
    if (ret) {
      connect_info_t coninfo;
      memset(&coninfo, 0, sizeof(coninfo));
      coninfo.state = CLOSED;
      coninfo.this_transportid = tcpls->next_transport_id++;
      coninfo.buffrag = malloc(sizeof(ptls_buffer_t));
      memset(coninfo.buffrag, 0, sizeof(ptls_buffer_t));
      coninfo.sendbuf = malloc(sizeof(ptls_buffer_t));
    
      if (properties->client.dest->ss_family == AF_INET) {
        con->dest = get_addr_from_sockaddr(tcpls->v4_addr_llist, (struct
              sockaddr_in *) properties->client.dest);
        if (!con->dest) {
          fprintf(stderr, "No addr matching properties->client.dest\n");
          return -1;
        }
      /* if we want to force a src */
        if (properties->client.src) {
          con->src = get_addr_from_sockaddr(tcpls->ours_v4_addr_llist, (struct
                sockaddr_in *) properties->client.dest);
          if (!con->src) {
            fprintf(stderr, "No addr matching properties->client.src\n");
            return -1;
          }
        }
      }
      else if (properties->client.dest->ss_family == AF_INET6) {
        con->dest6 = get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct
              sockaddr_in6 *) properties->client.dest);
        if (!con->dest6) {
          fprintf(stderr, "No addr matching properties->client.dest\n");
          return -1;
        }
        /* if we want to force a src */
        if (properties->client.src) {
          con->src6 = get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct
                sockaddr_in6 *) properties->client.src);
          if (!con->src6) {
            fprintf(stderr, "No addr matching properties->client.src\n");
            return -1;
          }
        }
      }
      list_add(tcpls->connect_infos, &coninfo);
      con = list_get(tcpls->connect_infos, tcpls->connect_infos->size-1);
      assert(con);
    }
    /* returns an error if the connection is already established or connecting*/
    if (con->state > CLOSED)
      return -1;
    if (con->dest)
      con->socket = socket(AF_INET, SOCK_STREAM, 0);
    else if (con->dest6)
      con->socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (con->src || con->src6) {
      con->src ? bind(con->socket, (struct sockaddr*) &con->src->addr,
          sizeof(con->src->addr)) : bind(con->socket, (struct sockaddr *)
          &con->src6->addr, sizeof(con->src6->addr));
    }
    sock = con->socket;
  }
  else if (properties && properties->socket) {
    sock = properties->socket;
    con = get_con_info_from_socket(tcpls, sock);
    if (!con)
      return -1;
  }
  if (!tls->is_server && !sock) {
    con = get_primary_con_info(tcpls);
    if (!con)
      goto Exit;
    sock = con->socket;
  }
  if (!properties ||(properties && !properties->client.mpjoin))
    tcpls->initial_socket = sock;

  int ret;
  ptls_buffer_t sendbuf;
  /** Sends the client hello (or the mpjoin client hello */
  ptls_buffer_init(&sendbuf, "", 0);
  if (!tls->is_server && ((ret = ptls_handshake(tls, &sendbuf, NULL, NULL,
          properties)) == PTLS_ERROR_IN_PROGRESS || ret == PTLS_ERROR_HANDSHAKE_IS_MPJOIN)) {
    rret = 0;
    while (rret < sendbuf.off) {
      if (properties && properties->client.zero_rtt) {
        con->state = CONNECTING;
        gettimeofday(&t_initial, NULL);
        memcpy(&t_previous, &t_initial, sizeof(t_previous));
        if (con->dest) {
          
          if ((ret = syscall_no_intercept(SYS_sendto, sock, sendbuf.base+rret, sendbuf.off-rret, MSG_FASTOPEN,
                  (struct sockaddr*) &con->dest->addr,  sizeof(con->dest->addr))) < 0) {
            perror("sendto failed");
            goto Exit;
          }
        }
        else if (con->dest6) {
          if ((ret = syscall_no_intercept(SYS_sendto , sock, sendbuf.base+rret, sendbuf.off-rret, MSG_FASTOPEN,
                  (struct sockaddr*) &con->dest6->addr,  sizeof(con->dest6->addr))) < 0) {
            perror("sendto failed");
            goto Exit;
          }
        }
      }
      else {
        if ((ret = syscall_no_intercept(SYS_sendto,sock, sendbuf.base+rret, sendbuf.off-rret, 0, NULL, 0)) < 0) {
          perror("send(2) failed");
          goto Exit;
        }
      }
      rret += ret;
    }
    /**
     * code flow for a TCPLS JOIN handshake to a join an existing connection
     */
    if (properties && properties->client.mpjoin) {
      /* we should get the TRANSPORTID_NEW -- NOTE; this is the size should not
       * exceed it */
      uint8_t recvbuf[256];
      while ((rret = syscall_no_intercept(SYS_read, sock, recvbuf, sizeof(recvbuf))) == -1 && errno == EINTR)
        ;
      if (rret == 0)
        goto Exit;
      if (properties->client.zero_rtt) {
        /*check whether tcp connected */
        int result;
        if ((ret = check_con_has_connected(tcpls, con, &result)) < 0) {
          goto Exit;
        }
        else if (result != 0) {
          perror("TFO failed?");
          goto Exit;
        }

        struct timeval timeout = {.tv_sec = 100, .tv_usec = 0};
        compute_client_rtt(con, &timeout, &t_initial, &t_previous);
        con->state = CONNECTED;
        ptls_buffer_init(con->sendbuf, "", 0);
      }

      /** Decrypt and apply the TRANSPORT_NEW */
      size_t input_off = 0;
      ptls_buffer_t decryptbuf;
      ptls_buffer_init(&decryptbuf, "", 0);
      size_t consumed;;
      input_off = 0;
      size_t input_size = rret;
      do {
        consumed = input_size - input_off;
        rret = ptls_receive(tls, &decryptbuf, con->buffrag, recvbuf + input_off, &consumed);
        input_off += consumed;
      } while (rret == 0 && input_off < input_size);

      ptls_buffer_dispose(&sendbuf);
      ptls_buffer_dispose(&decryptbuf);
      return rret;
    }
  }
  sendbuf.off = 0;
  ssize_t roff;
  uint8_t recvbuf[8192];
  do {
    while ((rret = syscall_no_intercept(SYS_read, sock, recvbuf, sizeof(recvbuf))) == -1 && errno == EINTR)
      ;
    if (rret == 0)
      goto Exit;
    if (properties->client.zero_rtt && con->state == CONNECTING) {
      int result;
      if (check_con_has_connected(tcpls, con, &result) < 0) {
        goto Exit;
      }
      else if (result != 0) {
        perror("TFO failed?");
        goto Exit;
      }
      con->state = CONNECTED;
    }
    roff = 0;
    do {
      ptls_buffer_init(&sendbuf, "", 0);
      size_t consumed = rret - roff;
      ret = ptls_handshake(tls, &sendbuf, recvbuf + roff, &consumed, properties);
      roff += consumed;
      if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && sendbuf.off != 0) {
        if ((rret = syscall_no_intercept(SYS_sendto, sock, sendbuf.base, sendbuf.off, 0, NULL, 0)) < 0) {
          perror("send(2) failed");
          goto Exit;
        }
      }
      ptls_buffer_dispose(&sendbuf);
    } while (ret == PTLS_ERROR_IN_PROGRESS && rret != roff);
  } while (ret == PTLS_ERROR_IN_PROGRESS);
  ptls_buffer_dispose(&sendbuf);
  return ret;
Exit:
  /** TODO Make callbacks for the different possible errors*/
  if (rret <= 0) {
    connect_info_t *con = get_con_info_from_socket(tcpls, sock);
    connection_close(tcpls, con);
  }
  ptls_buffer_dispose(&sendbuf);
  return -1;
}

/**
 * Server-side function called when the server knows it needs to attach a TCP
 * connection to a given tcpls_t session. It may be a MPJOIN TCP connection or
 * the primary connection. In case of the primary connection, the cookie is set
 * to NULL
 *
 * If this is a MPJOIN, this function check whether the received cookie is
 * valid. If it is, it creates a new connection and trigger a callback, marking
 * this con usable to attach streams.
 *
 * returns -1 upon error, and 0 if succeeded
 */

int tcpls_accept(tcpls_t *tcpls, int socket, uint8_t *cookie, uint32_t transportid) {
  /** check whether this socket has been already added */
  connect_info_t *conn = get_con_info_from_socket(tcpls, socket);
  if (conn)
    return 0;
  if (cookie) {
    uint8_t* cookie_in = list_get(tcpls->cookies, tcpls->cookies->size-1);
    if (!memcmp(cookie, cookie_in, COOKIE_LEN)) {
      list_remove(tcpls->cookies, cookie_in);
    }
    else {
      /** Cookie unvalid */
      return -1;
    }
  }
  struct sockaddr_storage ss;
  socklen_t sslen = sizeof(struct sockaddr_storage);
  memset(&ss, 0, sslen);
  connect_info_t newconn;
  memset(&newconn, 0, sizeof(connect_info_t));
  newconn.state = CONNECTED;
  newconn.socket = socket;
  newconn.buffrag = malloc(sizeof(ptls_buffer_t));
  memset(newconn.buffrag, 0, sizeof(ptls_buffer_t));
  newconn.sendbuf = malloc(sizeof(ptls_buffer_t));
  ptls_buffer_init(newconn.sendbuf, "", 0);
  newconn.this_transportid = tcpls->next_transport_id++;
  newconn.peer_transportid = transportid;
  tcpls->nbr_tcp_streams++;
  if (syscall_no_intercept(SYS_getsockname, socket, (struct sockaddr *) &ss, &sslen) < 0) {
    perror("getsockname(2) failed");
  }
  /** retrieve the correct addr */
  if (ss.ss_family == AF_INET) {
    tcpls_v4_addr_t *v4 = tcpls->ours_v4_addr_llist;
    while(v4) {
      if (!memcmp(&v4->addr, (struct sockaddr_in*) &ss, sizeof(struct sockaddr_in)))
        break;
      v4 = v4->next;
    }
    if (!v4)
      return -1;
    newconn.src = v4;
  }
  else if (ss.ss_family == AF_INET6) {
    tcpls_v6_addr_t *v6 = tcpls->ours_v6_addr_llist;
    while (v6) {
      if (!memcmp(&v6->addr, (struct sockaddr_in6*) &ss, sizeof(struct sockaddr_in6)))
        break;
      v6 = v6->next;
    }
    if (!v6)
      return -1;
    newconn.src6 = v6;
  }
  if (tcpls->tls->ctx->connection_event_cb) {
    tcpls->tls->ctx->connection_event_cb(CONN_OPENED, newconn.socket,
        newconn.this_transportid, tcpls->tls->ctx->cb_data);
  }
  /**
   * Send back a control message announcing the transport connection id of
   * this newconnn, and echo back the transport id.
   */
  if (cookie) {
    uint8_t input[4+4];
    memcpy(input, &newconn.this_transportid, 4);
    memcpy(&input[4], &transportid, 4);
    stream_send_control_message(tcpls->tls, tcpls->sendbuf, tcpls->tls->traffic_protection.enc.aead, input, TRANSPORT_NEW, 8);
    /*connect_info_t *con = get_primary_con_info(tcpls);*/
    int ret;
    ret = send(socket, tcpls->sendbuf->base+tcpls->send_start,
        tcpls->sendbuf->off-tcpls->send_start, 0);
    if (ret < 0) {
      /** TODO?  */
      return -1;
    }
    /* check whether we sent everything */
    if (tcpls->sendbuf->off == tcpls->send_start + ret) {
      tcpls->sendbuf->off = 0;
      tcpls->send_start = 0;
    }
  }
  else {
    newconn.is_primary = 1;
    /** this one may change in the future */
    tcpls->socket_primary = socket;
    /** not this one */
    tcpls->initial_socket = socket;
  }
  list_add(tcpls->connect_infos, &newconn);
  return 0;
}


/**
 * Create and attach locally a new stream to the main address if no addr
 * is provided; else attach to addr if we have a connection open to it
 *
 * src might be NULL to indicate default
 *
 * returns 0 if a stream is alreay attached for addr, or if some error occured
 */

streamid_t tcpls_stream_new(ptls_t *tls, struct sockaddr *src, struct sockaddr *dest) {
  /** Check first whether a stream isn't already attach to this addr */
  tcpls_t *tcpls = tls->tcpls;
  assert(tcpls);
  if (!dest)
    return 0;
  connect_info_t coninfo;
  memset(&coninfo, 0, sizeof(coninfo));
  connect_info_t *con_stored;
  int ret;
  tcpls_v4_addr_t *src_addr = NULL;
  tcpls_v6_addr_t *src6_addr = NULL;
  tcpls_v4_addr_t *dest_addr = NULL;
  tcpls_v6_addr_t *dest6_addr = NULL;
  if (src && src->sa_family == AF_INET) {
    src_addr = get_addr_from_sockaddr(tcpls->ours_v4_addr_llist, (struct sockaddr_in *)src);
    if (!src_addr) 
      return 0;
  }
  else if (src && src->sa_family == AF_INET6) {
    src6_addr = get_addr6_from_sockaddr(tcpls->ours_v6_addr_llist, (struct sockaddr_in6*) src);
    if (!src6_addr)
      return 0;
  }

  if (dest->sa_family == AF_INET) {
    dest_addr = get_addr_from_sockaddr(tcpls->v4_addr_llist,
        (struct sockaddr_in *) dest);
    assert(dest_addr); /**debugging mode*/
    if (!dest_addr)
      return 0;
    ret = get_con_info_from_addrs(tcpls, src_addr, dest_addr, NULL, NULL, &con_stored);
  }
  else if (dest->sa_family == AF_INET6) {
    dest6_addr = get_addr6_from_sockaddr(tcpls->v6_addr_llist, (struct sockaddr_in6 *) dest);
    assert(dest6_addr);
    if (!dest6_addr)
      return 0;
    ret = get_con_info_from_addrs(tcpls, NULL, NULL, src6_addr, dest6_addr, &con_stored);
  }
  else
    return 0;
  /** If we do not have any connection, let's create it */
  if (ret) {
    coninfo.socket = 0;
    coninfo.state = CLOSED;
    coninfo.this_transportid = tcpls->next_transport_id++;
    coninfo.buffrag = malloc(sizeof(ptls_buffer_t));
    memset(coninfo.buffrag, 0, sizeof(ptls_buffer_t));
    coninfo.sendbuf = malloc(sizeof(ptls_buffer_t));
    ptls_buffer_init(coninfo.sendbuf, "", 0);

    if (dest->sa_family == AF_INET) {
      /** NULL src means we use the default one */
      coninfo.src = src_addr;
      coninfo.dest = dest_addr;
      coninfo.src6 = NULL;
      coninfo.dest6 = NULL;
      /** Is this con using the primary addresses? */
      if (src && src_addr->is_primary && dest_addr->is_primary) {
        coninfo.is_primary = 1;
      }
      else if (!src && dest_addr->is_primary) {
        coninfo.is_primary = 1;
      }
    }
    else {
      /** We attach a stream to v6 interfaces */
      coninfo.src6 = src6_addr;
      coninfo.dest6 = dest6_addr;
      coninfo.src = NULL;
      coninfo.dest = NULL;
      if (src && src6_addr->is_primary && dest6_addr->is_primary) {
        coninfo.is_primary = 1;
      }
      else if (!src && dest6_addr->is_primary) {
        coninfo.is_primary = 1;
      }
    }
    /** copy coninfo into the heap allocated list */
    list_add(tcpls->connect_infos, &coninfo);
    /** get back this copy */
    con_stored = list_get(tcpls->connect_infos, tcpls->connect_infos->size-1);
  }
  tcpls_stream_t *stream = stream_helper_new(tcpls, con_stored);
  if (!stream)
    return 0;
  /**
   * remember to send a stream attach event with this stream the first time we
   * use it
   * */
  stream->need_sending_attach_event = 1;
  list_add(tcpls->streams, stream);
  return stream->streamid;
}

/**
 * Attach all newly created stream to the peer
 *
 * Usable only when the handshake has been done
 * sendnow instructs TCPLS to send the control message right now. If set to 0,
 * then the stream control message will be sent alongside the data within the
 * the first call to tcpls_send over the right streamid
 * 
 * Note, if stream attach events have not been sent, the application cannot use
 * the streamid to send messages
 */

int tcpls_streams_attach(ptls_t *tls, streamid_t streamid, int sendnow) {
  if (!ptls_handshake_is_complete(tls))
    return -1;
  tcpls_t *tcpls = tls->tcpls;
  tcpls_stream_t *stream;
  int ret = 0;
  ptls_aead_context_t *ctx_to_use = NULL;
  if (streamid) {
    stream = stream_get(tcpls, streamid);
    if (!stream && !stream->aead_enc)
      return -1;
    ctx_to_use = stream->aead_enc;
  }
  else
    ctx_to_use = tls->traffic_protection.enc.aead;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (stream->need_sending_attach_event) {
      uint8_t input[8];
      memset(input, 0, 8);
      /** send the stream id to the peer */
      memcpy(input, &stream->streamid, 4);
      memcpy(&input[4], &stream->con->peer_transportid, 4);
      stream_send_control_message(tls, stream->con->sendbuf, ctx_to_use, input, STREAM_ATTACH, 8);
      stream->con->send_stream_attach_in_sendbuf_pos = stream->con->sendbuf->off;
      stream->need_sending_attach_event = 0;
      tcpls->check_stream_attach_sent = 1;
      if (sendnow) {
        ret = send(stream->con->socket, stream->con->sendbuf->base+stream->con->send_start,
            stream->con->sendbuf->off-stream->con->send_start, 0);
        if (ret < 0) {
          /** Failover? */
          return -1;
        }
        /** Mark streams usables */
        check_stream_attach_have_been_sent(tcpls, ret);
        /** did we sent everything? =) */
        if (stream->con->sendbuf->off == stream->con->send_start + ret) {
          stream->con->sendbuf->off = 0;
          stream->con->send_start = 0;
          tcpls->check_stream_attach_sent = 0;
        }
        else if (ret+stream->con->send_start < stream->con->sendbuf->off) {
          stream->con->send_start += ret;
        }
      }
    }
  }
  return ret;
}


static int stream_close_helper(tcpls_t *tcpls, tcpls_stream_t *stream, int type, int sendnow) {
  uint8_t input[4];
  /** send the stream id to the peer */
  memcpy(input, &stream->streamid, 4);
  /** queue the message in the sending buffer */
  stream_send_control_message(tcpls->tls, stream->con->sendbuf, stream->aead_enc, input, type, 4);
  if (sendnow) {
    int ret;
    /*connect_info_t *con = get_primary_con_info(tcpls);*/
    ret = send(stream->con->socket, stream->con->sendbuf->base+stream->con->send_start,
        stream->con->sendbuf->off-stream->con->send_start, 0);
    if (ret < 0) {
      /** Failover ?  */
      return -1;
    }
    /* check whether we sent everything */
    if (stream->con->sendbuf->off == stream->con->send_start + ret) {
      stream->con->sendbuf->off = 0;
      stream->con->send_start = 0;
    }
    else if (ret+stream->con->send_start < stream->con->sendbuf->off) {
      stream->con->send_start += ret;
    }
  }
  else {
    stream->marked_for_close = 1;
    tcpls->streams_marked_for_close = 1;
  }
  stream->stream_usable = 0;
  return 0;
}

/**
 * Close a stream. If no stream are attached to any address, then the connection
 * is closed, and the application should call tcpls_free
 */
int tcpls_stream_close(ptls_t *tls, streamid_t streamid, int sendnow) {
  tcpls_t *tcpls = tls->tcpls;
  if (!tcpls->streams->size)
    return 0;
  tcpls_stream_t *stream = stream_get(tcpls, streamid);
  if (!stream)
    return -1;
  return stream_close_helper(tcpls, stream, STREAM_CLOSE, sendnow);
}

/**
 * Encrypts and sends input towards the primary path if available; else sends
 * towards the fallback path if the option is activated.
 *
 * Only send if the socket is within a connected state
 *
 * Send through streamid; or to the primary one if streamid = 0
 * Send through the primary; or switch the primary if some problem occurs
 */


ssize_t tcpls_send(ptls_t *tls, streamid_t streamid, const void *input, size_t nbytes) {
  tcpls_t *tcpls = tls->tcpls;
  int ret;
  tcpls_stream_t *stream;
  /*int is_failover_enabled = 0;*/
  /** Check the state of connections first do we have our primary connected tcp? */
  if ((!streamid && !tcpls->socket_primary) || !ptls_handshake_is_complete(tls)) {
    return -1;
  }
  /** Check whether we already have a stream open; if not, build a stream
   * with the default context */
  if (!tcpls->streams->size && ((tcpls->tls->is_server && tcpls->next_stream_id
          ==  2147483649) || (!tcpls->tls->is_server && tcpls->next_stream_id ==
            1))) {
    // NOTE: We only allow this behavior if we not yet received or sent any
    // stream_attach but somehow we have to send data

    // Create a stream with the default context, attached to primary IP
    connect_info_t *con = get_primary_con_info(tcpls);
    assert(con);
    tcpls->socket_rcv = con->socket;
    stream = stream_new(tls, tcpls->next_stream_id++, con, 1);
    if (tls->ctx->stream_event_cb) {
      tls->ctx->stream_event_cb(tcpls, STREAM_OPENED, stream->streamid, con->this_transportid,
          tls->ctx->cb_data);
    }
    stream->need_sending_attach_event = 0;

    uint8_t input[8];
    /** send the stream id to the peer */
    uint32_t peer_transportid = 0;
    memcpy(input, &stream->streamid, 4);
    memcpy(&input[4], &peer_transportid, 4);
    /** Add a stream message creation to the sending buffer ! */
    stream_send_control_message(tcpls->tls, stream->con->sendbuf, tls->traffic_protection.enc.aead, input, STREAM_ATTACH, 8);
    /** To check whether we sent it and if the stream becomes usable */
    stream->con->send_stream_attach_in_sendbuf_pos = stream->con->sendbuf->off;
    tcpls->check_stream_attach_sent = 1;
    list_add(tcpls->streams, stream);
  }
  else {
    stream = stream_get(tcpls, streamid);
    if (!stream)
      return -1;
    /** check whether we have to initiate this stream; it might have been
     * created before the handshake */
    if (!stream->aead_initialized) {
      if (new_stream_derive_aead_context(tls, stream, 1)) {
        return -1;
      }
      stream->aead_initialized = 1;
    }
    if (!stream->stream_usable)
      return -1;
  }
  if (!stream)
    return -1;

  // For compatibility with picotls; set the traffic_protection context
  // of the stream we want to use
  ptls_aead_context_t *remember_aead = tcpls->tls->traffic_protection.enc.aead;
  // get the right  aead context matching the stream id
  // This is done for compabitility with original PTLS's unit tests
  tcpls->tls->traffic_protection.enc.aead = stream->aead_enc;
  ret = ptls_send(tcpls->tls, stream->con->sendbuf, input, nbytes);
  tcpls->tls->traffic_protection.enc.aead = remember_aead;
  switch (ret) {
    /** Error in encryption -- TODO document the possibilties */
    case 0:
      break;
    default: return ret;
  }
  /** Send over the socket's stream */
  ret = syscall_no_intercept(SYS_sendto, stream->con->socket, stream->con->sendbuf->base+stream->con->send_start,
      stream->con->sendbuf->off-stream->con->send_start, 0, NULL, 0);
  if (ret < 0) {
    /** The peer reset the connection */
    stream->con->state = CLOSED;
    if (errno == ECONNRESET) {
      /** We might still have data in the socket, and we don't how much the
       * server read */
      /* Send a FAILOVER SIGNAL indicating the stream id */
      //send the last unacked records from streamid x the buffer
      //over the secondary path
      if (tls->ctx->failover == 1) {
        close(stream->con->socket);
        stream->con->socket = 0;
        /** get the fastest CONNECTED connection */
        connect_info_t *failover_con = get_best_con(tcpls);
        if (!failover_con) {
          /** We don't have anymore connection to failover ... this connection
           * can be closed */
          return -1;
        }
      }
      errno = 0; // reset after the problem is resolved =)
    }
    else if (errno == EPIPE) {
      /** Normal close (FIN) then RST */
    }
  }
  if (tcpls->check_stream_attach_sent) {
    check_stream_attach_have_been_sent(tcpls, ret);
  }
  /** did we sent everything? =) */
  if (stream->con->sendbuf->off == stream->con->send_start + ret) {
    stream->con->sendbuf->off = 0;
    stream->con->send_start = 0;
    tcpls->check_stream_attach_sent = 0;
    log_warn("sent all");
    return nbytes;
  }
  else if (ret+stream->con->send_start < stream->con->sendbuf->off) {
    stream->con->send_start += ret;
  }
  log_warn("not send all");
  return ret;
}

/**
 * Wait at most tv time over all stream sockets to be available for reading
 *
 * // TODO adding configurable callbacks for TCPLS events
 */

int tcpls_receive(ptls_t *tls, ptls_buffer_t *decryptbuf, struct timeval *tv) {
  fd_set rset;
  int ret, selectret;
  tcpls_t *tcpls = tls->tcpls;
  FD_ZERO(&rset);
  connect_info_t *con;
  int maxfd = 0;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->state != CLOSED) {
      FD_SET(con->socket, &rset);
      if (maxfd < con->socket)
        maxfd = con->socket;
    }
  }
  selectret = select(maxfd+1, &rset, NULL, NULL, tv);
  if (selectret <= 0) 
    return TCPLS_NO_DATA_RECEIVED;
  
  ret = 0;
  /* Default strategy -- One max record pulled for each connection */
  uint8_t input[PTLS_MAX_ENCRYPTED_RECORD_SIZE];
  for (int i =  0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (FD_ISSET(con->socket, &rset)) {
        ret = syscall_no_intercept(SYS_recvfrom, con->socket, input, PTLS_MAX_ENCRYPTED_RECORD_SIZE, 0, NULL, NULL);
      if (ret <= 0) {
        if (errno == ECONNRESET) {
          /** TODO next packets may need discarded? Or send an ack and wait! */
          /*ret = tcpls_receive(tls, buf, nbytes, tv);*/
        }
        if(errno == ENOENT)
          return TCPLS_SOCKET_IS_CLOSED;

        if(errno == EINPROGRESS)
          return TCPLS_CONNECT_IN_PROGRESS;
        
        if((errno == 0) && (ret == 0))
          return TCPLS_NO_DATA_RECEIVED;

        log_debug("connexion closed by tcpls_receive %d:%d:%d", con->socket, errno, ret);
        connection_close(tcpls, con);
        return ret;
      }
      else {
        /* We have stuff to decrypt */
        tcpls->socket_rcv = con->socket;
        int count_streams = count_streams_from_socket(tcpls, tcpls->socket_rcv);
        /** The first message over the fist connection, server-side, we do not
         * have streams attach yet, it is coming! */
        int rret = 1;
        size_t input_off = 0;
        size_t input_size = ret;
        size_t consumed;
        if (count_streams == 0) {
          while (input_off < input_size) {
            ptls_aead_context_t *remember_aead = tcpls->tls->traffic_protection.dec.aead;
            do {
              consumed = input_size - input_off;
              rret = ptls_receive(tls, decryptbuf, con->buffrag, input + input_off, &consumed);
              if (rret == 0)
                input_off += consumed;
            } while (rret == 0 && input_off < input_size);
            /** We may have received a stream attach that changed the aead*/
            tcpls->tls->traffic_protection.dec.aead = remember_aead;
            /* check whether we can pull records from our priority queue to
             * reorder */
          }
        }
        else {
          
          ptls_buffer_t *buf_to_use = NULL;
          for (int i = 0; i < tcpls->streams->size && rret; i++) {
            tcpls_stream_t *stream = list_get(tcpls->streams, i);
            if (stream->con->socket == tcpls->socket_rcv) {
              ptls_aead_context_t *remember_aead = tcpls->tls->traffic_protection.dec.aead;
              // get the right  aead context matching the stream id
              // This is done for compabitility with original PTLS's unit tests
              /** We possible have not stream attached server-side */
              if (stream) {
                tcpls->tls->traffic_protection.dec.aead = stream->aead_dec;
                buf_to_use = stream->con->buffrag;
              }
              input_off = 0;
              input_size = ret;
              do {
                consumed = input_size - input_off;
                rret = ptls_receive(tls, decryptbuf, buf_to_use, input + input_off, &consumed);
                input_off += consumed;
              } while (rret == 0 && input_off < input_size);
              tcpls->tls->traffic_protection.dec.aead = remember_aead;
              /* check whether we can pull records from our priority queue to
               * reorder */
            }
          }
        }
        if (rret != 0) {
          return ret;
        }
        /* merge rec_reording with decryptbuf if we can */
        multipath_merge_buffers(tcpls, decryptbuf);
      }
    }
  }
  if (heap_size(tcpls->priority_q))
    return TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ;
  else
    return TCPLS_OK;
}

/**
 * Sends a tcp option which has previously been registered with ptls_set...
 *
 * This function should be called after the handshake is complete for both party
 * */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, tcpls_enum_t type)
{
  tcpls_t *tcpls = tls->tcpls;
  if(tls->traffic_protection.enc.aead == NULL)
    return -1;

  if (tls->traffic_protection.enc.aead->seq >= 16777216)
    tls->needs_key_update = 1;

  if (tls->needs_key_update) {
    int ret;
    if ((ret = update_send_key(tls, sendbuf, tls->key_update_send_request)) != 0)
      return ret;
    tls->needs_key_update = 0;
    tls->key_update_send_request = 0;
  }
  /** Get the option */
  tcpls_options_t *option;
  int found = 0;
  for (int i = 0; i < tcpls->tcpls_options->size && !found; i++) {
    option = list_get(tcpls->tcpls_options, i);
    if (option->type == type && option->data->base && option->settopeer) {
      found = 1;
      break;
    }
  }
  if (!found)
    return -1;

  if (option->is_varlen) {
    /** We need to send the size of the option, which we might need to buffer */
    /** 4 bytes for the variable length, 2 bytes for the option value */
    uint8_t input[option->data->len + sizeof(option->type) + 4];
    memcpy(input, &option->type, sizeof(option->type));
    memcpy(input+sizeof(option->type), &option->data->len, 4);
    memcpy(input+sizeof(option->type)+4, option->data->base, option->data->len);
    return buffer_push_encrypted_records(tls, sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_CONTROL, input,
        option->data->len+sizeof(option->type)+4, tls->traffic_protection.enc.aead);
  }
  else {
    uint8_t input[option->data->len + sizeof(option->type)];
    memcpy(input, &option->type, sizeof(option->type));
    memcpy(input+sizeof(option->type), option->data->base, option->data->len);

    return buffer_push_encrypted_records(tls, sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_CONTROL, input,
        option->data->len+sizeof(option->type), tls->traffic_protection.enc.aead);
  }
}

/**=====================================================================================*/
/**
 * ptls_set_[TCPOPTION] needs to have been called first to initialize an option 
 */

/**
 * Set a timeout option (i.e., RFC5482) to transport within the TLS connection
 */
int ptls_set_user_timeout(ptls_t *ptls, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer) {
  int ret = 0;
  uint16_t *val = malloc(sizeof(uint16_t));
  if (val == NULL)
    return PTLS_ERROR_NO_MEMORY;
  *val = value | sec_or_min << 15;
  ret = tcpls_init_context(ptls, val, 2, USER_TIMEOUT, setlocal, settopeer);
  if (ret)
    return ret;
  if (setlocal) {
    ret = setlocal_usertimeout(ptls, *val);
  }
  return ret;
}

int ptls_set_happy_eyeball(ptls_t *ptls) {
  return 0;
}

int ptls_set_faileover(ptls_t *ptls, char *address) {
  return 0;
}

/**
 * Copy bpf_prog_bytecode inside ptls->tcpls_options
 */
int ptls_set_bpf_cc(ptls_t *ptls, const uint8_t *bpf_prog_bytecode, size_t bytecodelen,
    int setlocal, int settopeer) {
  int ret = 0;
  uint8_t* bpf_cc = NULL;
  if ((bpf_cc =  malloc(bytecodelen)) == NULL)
    return PTLS_ERROR_NO_MEMORY;
  memcpy(bpf_cc, bpf_prog_bytecode, bytecodelen);
  ret = tcpls_init_context(ptls, bpf_cc, bytecodelen, BPF_CC, setlocal, settopeer);
  if (ret)
    return -1;
  if (setlocal){
    ret = setlocal_bpf_cc(ptls, bpf_prog_bytecode, bytecodelen);
  }
  return ret;
}

/*===================================Internal========================================*/

static int cmp_mpseq(void *mpseq1, void *mpseq2) {
  
    register uint32_t key1_v = *((uint32_t*)mpseq1);
    register uint32_t key2_v = *((uint32_t*)mpseq2);

    // Perform the comparison
    if (key1_v < key2_v)
        return -1;
    else if (key1_v == key2_v)
        return 0;
    else return 1;
}

/**
 *
 */

static int multipath_merge_buffers(tcpls_t *tcpls, ptls_buffer_t *decryptbuf) {
  // We try to pull bytes from the reordering buffer only if there is something
  // within our priorty queue, and we have > 0 nbytes to get to the application
  
  uint32_t initial_pos = decryptbuf->off;
  int ret;
  if (heap_size(tcpls->priority_q) > 0) {
    uint32_t *mpseq;
    uint32_t *buf_position_data;
    ret = heap_min(tcpls->priority_q, (void **) &mpseq, (void **)&buf_position_data);
    while (ret && *mpseq == tcpls->next_expected_mpseq) {
      size_t length = *(size_t *) (tcpls->rec_reordering->base+*buf_position_data);
      ptls_buffer_pushv(decryptbuf, tcpls->rec_reordering->base+*buf_position_data+sizeof(size_t), length);
      heap_delmin(tcpls->priority_q, (void**)&mpseq, (void**)&buf_position_data);
      tcpls->next_expected_mpseq++;
      free(mpseq);
      free(buf_position_data);
      ret = heap_min(tcpls->priority_q, (void **) &mpseq, (void **) &buf_position_data);
    }
  }
  /** we have nothing left in the heap and no fragments, we can clean rec_reordering! */
  if (heap_size(tcpls->priority_q) == 0 && tcpls->rec_reordering->off)
    ptls_buffer_dispose(tcpls->rec_reordering);
  return decryptbuf->off-initial_pos;
Exit:
  return -1;
}



/**
 * Verify whether the position of the stream attach event event has been
 * consumed by a blocking send system call; as soon as it has been, the stream
 * is usable
 */
static void check_stream_attach_have_been_sent(tcpls_t *tcpls, int consumed) {
  tcpls_stream_t *stream;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (!stream->stream_usable && stream->con->send_stream_attach_in_sendbuf_pos <=
        consumed + stream->con->send_start) {
      stream->stream_usable = 1;
      stream->con->send_stream_attach_in_sendbuf_pos = 0; // reset it
      /** fire callback ! TODO */
    }
  }
}

static tcpls_v4_addr_t *get_addr_from_sockaddr(tcpls_v4_addr_t *llist, struct sockaddr_in *addr) {
  if (!addr)
    return NULL;
  tcpls_v4_addr_t *current = llist;
  while (current) {
    if (!memcmp(&current->addr, addr, sizeof(*addr)))
      return current;
    current = current->next;
  }
  return NULL;
}

static tcpls_v6_addr_t *get_addr6_from_sockaddr(tcpls_v6_addr_t *llist, struct sockaddr_in6 *addr6) {
  if (!addr6)
    return NULL;
  tcpls_v6_addr_t *current = llist;
  while (current) {
    if (!memcmp(&current->addr, addr6, sizeof(*addr6)))
      return current;
    current = current->next;
  }
  return NULL;
}

static int handle_connect(tcpls_t *tcpls, tcpls_v4_addr_t *src, tcpls_v4_addr_t
    *dest, tcpls_v6_addr_t *src6, tcpls_v6_addr_t *dest6, unsigned short afinet,
    int *nfds, connect_info_t *coninfo, int sd) {
  int ret = get_con_info_from_addrs(tcpls, src, dest, src6, dest6, &coninfo);
  if (ret) {

    coninfo->socket = sd;
    coninfo->state = CLOSED;
    coninfo->this_transportid = tcpls->next_transport_id++;
    coninfo->buffrag = malloc(sizeof(ptls_buffer_t));
    memset(coninfo->buffrag, 0, sizeof(ptls_buffer_t));
    coninfo->sendbuf = malloc(sizeof(ptls_buffer_t));
    ptls_buffer_init(coninfo->sendbuf, "", 0);

    if (afinet == AF_INET) {
      coninfo->src = src;
      coninfo->dest = dest;
      coninfo->src6 = NULL;
      coninfo->dest6 = NULL;
      if ((src && src->is_primary) && dest->is_primary)
        coninfo->is_primary = 1;
      else if (!src && dest->is_primary)
        coninfo->is_primary = 1;
    }
    else {
      coninfo->src6 = src6;
      coninfo->dest6 = dest6;
      coninfo->src = NULL;
      coninfo->dest = NULL;
      if ((src6 && src6->is_primary) && dest6->is_primary)
        coninfo->is_primary = 1;
      else if (!src6 && dest6->is_primary)
        coninfo->is_primary = 1;
    }
  }

  if (coninfo->state == CLOSED) {
    /** we can connect */
    if (!coninfo->socket) {
      if ((coninfo->socket = socket(afinet, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
        return -1;
      }
    }
    /** try to connect */
    if (src || src6) {
      src ? bind(coninfo->socket, (struct sockaddr*) &src->addr,
          sizeof(src->addr)) : bind(coninfo->socket, (struct sockaddr *)
          &src6->addr, sizeof(src6->addr));
    }
    if (afinet == AF_INET) {
      if (syscall_no_intercept(SYS_connect, coninfo->socket, (struct sockaddr*) &dest->addr,
            sizeof(dest->addr)) < 0 && errno != EINPROGRESS) {
        connection_close(tcpls, coninfo);
        return -1;
      }
    }
    else {
      if (syscall_no_intercept(SYS_connect, coninfo->socket, (struct sockaddr*) &dest6->addr,
            sizeof(dest6->addr)) < 0 && errno != EINPROGRESS) {
        coninfo->state = CLOSED;
        close(coninfo->socket);
        return -1;
      }
    }
    coninfo->state = CONNECTING;
    *nfds = *nfds + 1;
  }
  else if (coninfo->state == CONNECTING) {
    *nfds = *nfds + 1;
  }
  if (ret) {
    list_add(tcpls->connect_infos, coninfo);
  }
  return 0;
}

/**
 * Note: con should point to the element in tcpls->connect_info
 */

static tcpls_stream_t *stream_helper_new(tcpls_t *tcpls, connect_info_t *con) {
  tcpls_stream_t *stream = NULL;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    /* we alreay have a stream attached with this con! */
    if (!memcmp(stream->con, con, sizeof(*con)))
      return NULL;
  }
  stream = stream_new(tcpls->tls, tcpls->next_stream_id++, con, 1);
  return stream;
}


/**
 * Send a message to the peer to:
 *    - initiate a new stream
 *    - close a new stream
 *    - send a acknowledgment
 */

static int stream_send_control_message(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_aead_context_t *aead,
    const void *inputinfo, tcpls_enum_t tcpls_message, uint32_t message_len) {
  uint8_t input[message_len+sizeof(tcpls_message)];
  memcpy(input, &tcpls_message, sizeof(tcpls_message));
  memcpy(input+sizeof(tcpls_message), inputinfo, message_len);
  return buffer_push_encrypted_records(tls, sendbuf,
      PTLS_CONTENT_TYPE_TCPLS_CONTROL, input,
      message_len+sizeof(tcpls_message), aead);
}

static int  tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer) {
  tcpls_t *tcpls = ptls->tcpls;
  ptls->ctx->support_tcpls_options = 1;
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  tcpls_options_t *option = NULL;
  int found_one = 0;
  for (int i = 0; i < tcpls->tcpls_options->size; i++) {
    /** already set or Not yet set */
    option = list_get(tcpls->tcpls_options, i);
    if (option->type == type && option->data->base) {
      found_one = 1;
      break;
    }
  }
  /** let's create it and add it to the list */
  if (!found_one) {
    option = malloc(sizeof(tcpls_options_t));
    option->data = malloc(sizeof(ptls_iovec_t));
    memset(option->data, 0, sizeof(ptls_iovec_t));
    option->type = type;
    option->is_varlen = 0;
  }

  option->setlocal = setlocal;
  option->settopeer = settopeer;

  switch (type) {
    case USER_TIMEOUT:
      if (found_one) {
        free(option->data->base);
      }
      option->is_varlen = 0;
      *option->data = ptls_iovec_init(data, sizeof(uint16_t));
      option->type = USER_TIMEOUT;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    case MULTIHOMING_v4:
    case MULTIHOMING_v6:
      if (option->data->len) {
        free(option->data->base);
      }
      *option->data = ptls_iovec_init(data, datalen);
      option->type = type;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    case BPF_CC:
      if (option->data->len) {
        /** We already had one bpf cc, free it */
        free(option->data->base);
      }
      option->is_varlen = 1;
      *option->data = ptls_iovec_init(data, datalen);
      option->type = BPF_CC;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    default:
      break;
  }
  return -1;
}

/**
 * Handle TCPLS extension
 *
 * Note: the implementation currently does not handle malformed options (we
 * should check our parsing and send alert messages upon inapropriate data)
 */

int handle_tcpls_control(ptls_t *ptls, tcpls_enum_t type,
    const uint8_t *input, size_t inputlen) {
  if (!ptls->tcpls->tcpls_options_confirmed)
    return -1;
  switch (type) {
    case CONNID:
      {
        assert(inputlen == CONNID_LEN); /*debug*/
        if (inputlen != CONNID_LEN)
          return PTLS_ALERT_ILLEGAL_PARAMETER;
        memcpy(ptls->tcpls->connid, input, inputlen);
        return 0;
      }
    case COOKIE:
      {
        assert(inputlen == COOKIE_LEN);
        uint8_t *cookie = (uint8_t*) input;
        list_add(ptls->tcpls->cookies, cookie);
        return 0;
      }
    case USER_TIMEOUT:
      {
        uint16_t *nval = malloc(inputlen);
        *nval = *(uint16_t *)input;
        int ret;
        /**nval = ntoh16(input);*/
        ret= tcpls_init_context(ptls, nval, 2, USER_TIMEOUT, 1, 0);
        if (ret)
          return -1; /** Should define an appropriate error code */
        return setlocal_usertimeout(ptls, *nval);
      }
      break;
    case MULTIHOMING_v4:
      {
        /** input should contain a list of v4 IP addresses */
        int ret = 0;
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443); /** Not great; but it's fine for a POC; else we also need
                                        to reference the port somewhere */
        uint8_t nbr = *input;
        int offset = 0;
        while(nbr && !ret) {
          memcpy(&addr.sin_addr, input+1+offset, sizeof(struct in_addr));
          offset+=sizeof(struct in_addr);
          ret = tcpls_add_v4(ptls, &addr, 0, 0, 0);
          nbr--;
        }
        return ret;
      }
      break;
    case MULTIHOMING_v6:
      {
      /** input should contain a list of v6 IP addresses */
        int ret = 0;
        struct sockaddr_in6 addr;
        bzero(&addr, sizeof(addr));
        addr.sin6_family = AF_INET6;
        uint8_t nbr = *input;
        int offset = 0;
        while (nbr && !ret) {
          memcpy(&addr.sin6_addr, input+1+offset, sizeof(struct in6_addr));
          offset+=sizeof(struct in6_addr);
          ret = tcpls_add_v6(ptls, &addr, 0, 0, 0);
          nbr--;
        }
        return ret;
      }
      break;
    case TRANSPORT_NEW:
      {
        uint32_t peer_transportid = *(uint32_t*) input;
        uint32_t our_transportid = *(uint32_t*) &input[4];
        connect_info_t *con;
        for (int i = 0; i < ptls->tcpls->connect_infos->size; i++) {
          con = list_get(ptls->tcpls->connect_infos, i);
          if (con->this_transportid == our_transportid) {
            con->peer_transportid = peer_transportid;
            return 0;
          }
        }
        return PTLS_ERROR_CONN_NOT_FOUND;
      }
    case STREAM_CLOSE_ACK:
    case STREAM_CLOSE:
      {
       // TODO encoding with network order and decoding to host order
       streamid_t streamid = *(streamid_t *)input;
       tcpls_stream_t *stream = stream_get(ptls->tcpls, streamid);
       if (!stream) {
         /** What to do? this should not happen - Close the connection*/
         return PTLS_ERROR_STREAM_NOT_FOUND;
       }
       if (ptls->ctx->stream_event_cb)
         ptls->ctx->stream_event_cb(ptls->tcpls, STREAM_CLOSED, stream->streamid,
             stream->con->this_transportid, ptls->ctx->cb_data);

       if (type == STREAM_CLOSE) {
         stream_close_helper(ptls->tcpls, stream, STREAM_CLOSE_ACK, 1);
       }
       else if (ptls->ctx->connection_event_cb && type == STREAM_CLOSE_ACK) {
         /** if this is the last stream attached to this */
         if (count_streams_from_socket(ptls->tcpls, stream->con->socket) == 1) {
           connection_close(ptls->tcpls, stream->con);
         }
       }
       /** Free AEAD contexts */
       stream_free(stream);
       list_remove(ptls->tcpls->streams, stream);
       return 0;
      }
      break;
    case STREAM_ATTACH:
      {
        //TODO fix this with sending with network order and receiving with host
        //order
        streamid_t streamid = *(streamid_t *) input;
        uint32_t transportid = *(uint32_t*) &input[4];
        connect_info_t *con;
        int found = 0;
        for (int i = 0; i < ptls->tcpls->connect_infos->size && !found; i++) {
          con = list_get(ptls->tcpls->connect_infos, i);
          if (con->this_transportid == transportid) {
            found = 1;
          }
        }
        if (!found)
          return PTLS_ERROR_CONN_NOT_FOUND;
        /** an absolute number that should not reduce at stream close */
        ptls->tcpls->nbr_of_peer_streams_attached++;
        tcpls_stream_t *stream = stream_new(ptls, streamid, con, 0);
        stream->stream_usable = 1;
        stream->need_sending_attach_event = 0;
        ptls->traffic_protection.dec.aead = stream->aead_dec;
        /** trigger callback */
        if (ptls->ctx->stream_event_cb) {
          ptls->ctx->stream_event_cb(ptls->tcpls, STREAM_OPENED, stream->streamid,
              con->this_transportid, ptls->ctx->cb_data);
        }
        if (!stream) {
          return PTLS_ERROR_STREAM_NOT_FOUND;
        }
        list_add(ptls->tcpls->streams, stream);
        return 0;
      }
      break;
    case FAILOVER:
      {
        streamid_t streamid = *(streamid_t *)input;
        connect_info_t *con = get_con_info_from_socket(ptls->tcpls, ptls->tcpls->socket_rcv);
        /** move streamid's con to this con */
        tcpls_stream_t *stream = stream_get(ptls->tcpls, streamid);
        if (!stream)
          return PTLS_ERROR_STREAM_NOT_FOUND;
        stream->con = con;
        //TODO callback notification that the stream has moved
        return 0;
      }
        break;
    case BPF_CC:
      {
        int ret;
        /** save the cc; will be freed at tcpls_free */
        uint8_t *bpf_prog = malloc(inputlen);
        memcpy(bpf_prog, input, inputlen);
        ret = tcpls_init_context(ptls, bpf_prog, inputlen, BPF_CC, 1, 0);
        if (ret)
          return -1;
        return setlocal_bpf_cc(ptls, bpf_prog, inputlen);
      }
      break;
    default:
      fprintf(stderr, "Unsuported option?");
      return -1;
  }
 return 0;
}

/**
 * Handle single tcpls data record
 */


int handle_tcpls_data_record(ptls_t *tls, struct st_ptls_record_t *rec)
{
  tcpls_t *tcpls = tls->tcpls;
  uint32_t mpseq = *(uint32_t*) rec->fragment;
  int ret = 0;
  if (tcpls->next_expected_mpseq == mpseq) {
    // then we push this fragment in the received buffer
    tcpls->next_expected_mpseq++;
    return 0;
  }
  else {
    // push the record to the reordering buffer, and add it to the priority
    // queue
    if (tcpls->rec_reordering->base == NULL) {
      ptls_buffer_init(tcpls->rec_reordering, "", 0);
    }
    uint32_t *mpseq_ptr = (uint32_t*) malloc(sizeof(uint32_t));
    *mpseq_ptr = mpseq;
    ptls_buffer_pushv(tcpls->rec_reordering, &rec->length,
        sizeof(rec->length));
    ptls_buffer_pushv(tcpls->rec_reordering, rec->fragment, rec->length);
    /** contains length + payload, point to the length*/
    uint32_t *buf_position_data = (uint32_t*) malloc(sizeof(uint32_t));
    *buf_position_data = tcpls->rec_reordering->off-rec->length-sizeof(rec->length);
    heap_insert(tcpls->priority_q, (void *)mpseq_ptr, (void*)buf_position_data);
    return 1;
  }
Exit:
  return ret;
}

/**
 * Handle single control record and varlen options with possibly many records
 *
 * varlen records must be sent over the same stream for appropriate buffering
 * //TODO make the buffering per-stream!
 */

int handle_tcpls_control_record(ptls_t *tls, struct st_ptls_record_t *rec)
{
  int ret = 0;
  tcpls_enum_t type;
  uint8_t *init_buf = NULL;
  /** Assumes a TCPLS option holds within 1 record ; else we need to buffer the
   * option to deliver it to handle_tcpls_cotrol 
   * */
  if (!tls->tcpls_buf) {
    if ((tls->tcpls_buf = malloc(sizeof(*tls->tcpls_buf))) == NULL) {
      ret = PTLS_ERROR_NO_MEMORY;
      goto Exit;
    }
    memset(tls->tcpls_buf, 0, sizeof(*tls->tcpls_buf));
  }

  type = *(tcpls_enum_t*) rec->fragment;
  /** Check whether type is a variable len option */
  if (is_varlen(type)){
    /*size_t optsize = ntoh32(rec->fragment+sizeof(type));*/
    uint32_t optsize = (uint32_t) *(rec->fragment+sizeof(type));
    if (optsize > PTLS_MAX_PLAINTEXT_RECORD_SIZE-sizeof(type)-4) {
      /** We need to buffer it */
      /** Check first if the buffer has been initialized */
      if (!tls->tcpls_buf->base) {
        if ((init_buf = malloc(VARSIZE_OPTION_MAX_CHUNK_SIZE)) == NULL) {
          ret = PTLS_ERROR_NO_MEMORY;
          goto Exit;
        }
        ptls_buffer_init(tls->tcpls_buf, init_buf, VARSIZE_OPTION_MAX_CHUNK_SIZE);
      }
      /** always reserve memory (won't if enough left) */
      if ((ret = ptls_buffer_reserve(tls->tcpls_buf, rec->length-sizeof(type)-4)) != 0)
        goto Exit;
      memcpy(tls->tcpls_buf->base+tls->tcpls_buf->off, rec->fragment+sizeof(type)+4, rec->length-sizeof(type)-4);
      tls->tcpls_buf->off += rec->length - sizeof(type)-4;
      if (ret)
        goto Exit;
      if (tls->tcpls_buf->off == optsize) {
        /** We have all of it */
        ret = handle_tcpls_control(tls, type, tls->tcpls_buf->base, optsize);
        ptls_buffer_dispose(tls->tcpls_buf);
      }
      return ret;
    }
    else {
      return handle_tcpls_control(tls, type, rec->fragment+sizeof(type)+4, optsize);
    }
  }
  /** We assume that only Variable size options won't hold into 1 record */
  return handle_tcpls_control(tls, type, rec->fragment+sizeof(type), rec->length-sizeof(type));

Exit:
  ptls_buffer_dispose(tls->tcpls_buf);
  /*free(tls->tcpls_buf);*/
  return ret;
}

static int setlocal_usertimeout(ptls_t *ptls, int val) {
  return 0;
}


static int setlocal_bpf_cc(ptls_t *ptls, const uint8_t *prog, size_t proglen) {
  return 0;
}


/*=====================================utilities======================================*/

static struct timeval timediff(struct timeval *t_current, struct timeval *t_init) {
  struct timeval diff;

  diff.tv_sec = t_current->tv_sec - t_init->tv_sec;
  diff.tv_usec = t_current->tv_usec - t_init->tv_usec;

  if (diff.tv_usec < 0) {
    diff.tv_usec += 1000000;
    diff.tv_sec--;
  }
  return diff;
}

static void compute_client_rtt(connect_info_t *con, struct timeval *timeout,
    struct timeval *t_initial, struct timeval *t_previous) {

  struct timeval t_current;
  gettimeofday(&t_current, NULL);
  
  int new_val =
    timeout->tv_sec*(uint64_t)1000000+timeout->tv_usec
    - (t_current.tv_sec*(uint64_t)1000000+t_current.tv_usec
        - t_previous->tv_sec*(uint64_t)1000000-t_previous->tv_usec);

  memcpy(t_previous, &t_current, sizeof(*t_previous));

  int sec = new_val / 1000000;
  timeout->tv_sec = sec;
  timeout->tv_usec = new_val - timeout->tv_sec*(uint64_t)1000000;

  con->connect_time = timediff(&t_current, t_initial);
  con->state = CONNECTED;
}

static int check_con_has_connected(tcpls_t *tcpls, connect_info_t *con, int *result) {
  socklen_t reslen = sizeof(*result);
  if (getsockopt(con->socket, SOL_SOCKET, SO_ERROR, result, &reslen) < 0) {
    return -1;
  }
  if (*result != 0) {
    fprintf(stderr, "Connection failed: %s\n", strerror(*result));
    return -1;
  }
  if (*result == 0) {
    if (tcpls->tls->ctx->connection_event_cb) {
      tcpls->tls->ctx->connection_event_cb(CONN_OPENED, con->socket,
                  con->this_transportid, tcpls->tls->ctx->cb_data);
    }
  }
  return 0;
}

/**
 * Compute the value IV to use for the next stream.
 *
 * It allows the counter to start at 0 using the same key for all streams, and
 * MIN_LOWIV_STREAM_INCREASE prevent the AES counter to have a chance to overlap
 * between calls.
 *
 * TODO debug
 **/

static void stream_derive_new_aead_iv(ptls_t *tls, uint8_t *iv, int iv_size,
    streamid_t streamid, int is_ours) {
  return;
  int mult;
  /** server next_stream_id starts at 2**31 */
  if (tls->is_server && is_ours) {
    mult = streamid-2147483648-1;
  }
  else {
    mult = streamid-1;
  }
  /** TLS 1.3 supports ciphers with two different IV size so far */
  if (iv_size == 12) {
    uint32_t low_iv = (uint32_t) iv[8];
    /** if over uin32 MAX; it should properly wrap arround */
    printf("low iv: %u; mult: %d\n", low_iv, mult);
    low_iv += mult * MIN_LOWIV_STREAM_INCREASE;
    printf("low iv: %u; mult: %d\n", low_iv, mult);
    /*if (tls->is_server) {*/
      /*[>set the leftmost bit to 1<]*/
      /*low_iv |= (1 << 31);*/
    /*}*/
    /*else {*/
      /* client initiated streams would have the left most bit of the low_iv
       * part always to 0 */
      /*low_iv |= (0 << 31);*/
    /*}*/
    memcpy(&iv[8], &low_iv, 4);
  }
  /** 16 bytes IV */
  else if (iv_size == 16) {
    uint64_t low_iv = (uint64_t) iv[8];
    low_iv += mult * MIN_LOWIV_STREAM_INCREASE;
    if (tls->is_server)
      low_iv |= (1UL << 63);
    else
      low_iv |= (0UL << 63);
    memcpy(&iv[8], &low_iv, 8);
  }
  else {
    /** TODO; change the return type; and return -1 here */
    printf("THAT MUST NOT HAPPEN :) \n");
  }
}

/**
 * Derive new aead context for the new stream; i.e., currently use a tweak on
 * the IV but the same key
 *
 * Using a different salt to derive another secret and then derive new keys/IVs
 * is another possible solution
 *
 * Note: less keys => better security
 *
 */

// TODO FIXBUG IV derivation
static int new_stream_derive_aead_context(ptls_t *tls, tcpls_stream_t *stream, int is_ours) {
  
  struct st_ptls_traffic_protection_t *ctx_enc = &tls->traffic_protection.enc;
  struct st_ptls_traffic_protection_t *ctx_dec = &tls->traffic_protection.dec;
  stream->aead_enc = ptls_aead_new(tls->cipher_suite->aead,
      tls->cipher_suite->hash, 1, ctx_enc->secret,
      tls->ctx->hkdf_label_prefix__obsolete);
  if (!stream->aead_enc)
    return PTLS_ERROR_NO_MEMORY;
  /** now change the lower half bits of the IV to avoid collisions */
  stream_derive_new_aead_iv(tls, stream->aead_enc->static_iv,
      tls->cipher_suite->aead->iv_size, stream->streamid, is_ours);
  stream->aead_dec = ptls_aead_new(tls->cipher_suite->aead,
      tls->cipher_suite->hash, 0, ctx_dec->secret,
      tls->ctx->hkdf_label_prefix__obsolete);
  if (stream->aead_dec)
    return PTLS_ERROR_NO_MEMORY;
  stream_derive_new_aead_iv(tls, stream->aead_dec->static_iv,
      tls->cipher_suite->aead->iv_size, stream->streamid, is_ours);
  return 0;
}

/**
 * Create a new stream and attach it to a local addr.
 * if addr is set, addr6 must be NULL;
 * if addr6 is set, addr must be NULL;
 * 
 * is_ours tells whether this stream has been initiated by us (is_our = 1), or
 * initiated by the peer (STREAM_ATTACH event, is_ours = 0)
 */

static tcpls_stream_t *stream_new(ptls_t *tls, streamid_t streamid,
    connect_info_t *con, int is_ours) {
  tcpls_stream_t *stream = malloc(sizeof(*stream));
  memset(stream, 0, sizeof(tcpls_stream_t));
  stream->streamid = streamid;
  /** TODO figure out a good default size for the control flow */
  /*stream->send_queue = tcpls_record_queue_new(500);*/

  stream->con = con;
  stream->stream_usable = 0;
  if (ptls_handshake_is_complete(tls)) {
  /** Now derive a correct aead context for this stream */
    new_stream_derive_aead_context(tls, stream, is_ours);
    stream->aead_initialized = 1;
    stream->stream_usable = 1;
  }
  else {
    stream->aead_enc = NULL;
    stream->aead_dec = NULL;
    stream->aead_initialized = 0;
  }
  return stream;
}

static int count_streams_from_socket(tcpls_t *tcpls, int socket) {
  tcpls_stream_t *stream;
  int count = 0;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (socket == stream->con->socket)
      count++;
  }
  return count;
}

/**
 * TODO: improve by adding an offset to stream id and get streams in O(1)
 */

tcpls_stream_t *stream_get(tcpls_t *tcpls, streamid_t streamid) {
  if (!tcpls->streams)
    return NULL;
  tcpls_stream_t *stream;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (stream->streamid == streamid)
      return stream;
  }
  return NULL;
}

static void stream_free(tcpls_stream_t *stream) {
  if (!stream)
    return;
  ptls_aead_free(stream->aead_enc);
  ptls_aead_free(stream->aead_dec);
}

/**
 * Get the fastest CONNECTED con
 */

static connect_info_t *get_best_con(tcpls_t *tcpls) {
  connect_info_t *con;
  connect_info_t *con_fastest = list_get(tcpls->connect_infos, 0);
  for (int i = 1; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->state == CONNECTED && (cmp_times(&con_fastest->connect_time,
            &con->connect_time) < 0 || con_fastest->state != CONNECTED))
      con_fastest = con;
  }
  return con_fastest;
}

static connect_info_t *get_con_info_from_socket(tcpls_t *tcpls, int socket) {
  connect_info_t *con;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->socket == socket)
      return con;
  }
  return NULL;
}

/**
 * look over the connect_info list and set coninfo to the right connect_info
 */
static int get_con_info_from_addrs(tcpls_t *tcpls, tcpls_v4_addr_t *src,
    tcpls_v4_addr_t *dest, tcpls_v6_addr_t *src6, tcpls_v6_addr_t *dest6,
    connect_info_t **coninfo)
{
  connect_info_t *con;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (dest && con->dest) {
      if (src && !memcmp(src, con->src, sizeof(*src)) && !memcmp(dest,
            con->dest, sizeof(*dest))) {
        *coninfo = con;
        return 0;
      }
      else if (!src && !memcmp(dest, con->dest, sizeof(*dest))) {
        *coninfo = con;
        return 0;
      }
    }
    else if (dest6 && con->dest6) {
      if (src6 && !memcmp(src6, con->src6, sizeof(*src6)) && !memcmp(dest6,
            con->dest6, sizeof(*dest6))) {
        *coninfo = con;
        return 0;
      }
      else if (!src6  && !memcmp(dest6, con->dest6, sizeof(*dest6))) {
        *coninfo = con;
        return 0;
      }
    }
  }
  return -1;
}

static connect_info_t * get_primary_con_info(tcpls_t *tcpls) {
  connect_info_t *con;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->is_primary)
      return con;
  }
  return NULL;
}

/**
 * ret < 0 : t1 < t2
 * ret == 0: t1 == t2
 * ret > 0 : t1 > t2
 */
static int cmp_times(struct timeval *t1, struct timeval *t2) {
  int64_t val = t1->tv_sec*1000000 + t1->tv_usec - t2->tv_sec*1000000-t2->tv_usec;
  if (val < 0)
    return -1;
  else if (val == 0)
    return 0;
  else
    return 1;
}

/**
 * If a a primary address has not been set by the application, set the
 * address for which we connected the fastest as primary
 */

static void _set_primary(tcpls_t *tcpls) {
  int has_primary = 0;
  connect_info_t *con, *primary_con;
  primary_con = list_get(tcpls->connect_infos, 0);
  assert(primary_con);
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->is_primary) {
      has_primary = 1;
      break;
    }
    if (cmp_times(&primary_con->connect_time, &con->connect_time) > 0)
      primary_con = con;
  }
  if (has_primary) {
    tcpls->socket_primary = primary_con->socket;
    return;
  }
  primary_con->is_primary = 1;
  tcpls->socket_primary = primary_con->socket;
  /* set the primary bit to the addresses */
  if (primary_con->src)
    primary_con->src->is_primary = 1;
  if (primary_con->src6)
    primary_con->src6->is_primary = 1;
  if (primary_con->dest)
    primary_con->dest->is_primary = 1;
  if (primary_con->dest6)
    primary_con->dest6->is_primary = 1;
}

static int is_varlen(tcpls_enum_t type) {
  return (type == BPF_CC);
}

void ptls_tcpls_options_free(tcpls_t *tcpls) {
  if (!tcpls)
    return;
  tcpls_options_t *option = NULL;
  for (int i = 0; i < tcpls->tcpls_options->size; i++) {
    option = list_get(tcpls->tcpls_options, i);
    if (option->data->base) {
      free(option->data->base);
    }
    free(option->data);
  }
  list_free(tcpls->tcpls_options);
  tcpls->tcpls_options = NULL;
}

void connection_close(tcpls_t *tcpls, connect_info_t *con) {
  con->state = CLOSED;
  close(con->socket);
  tcpls->tls->ctx->connection_event_cb(CONN_CLOSED, con->socket, con->this_transportid,
      tcpls->tls->ctx->cb_data);
  con->socket = 0;
  tcpls->nbr_tcp_streams--;
  ptls_buffer_dispose(con->sendbuf);
}

void tcpls_free(tcpls_t *tcpls) {
  if (!tcpls)
    return;
  ptls_buffer_dispose(tcpls->recvbuf);
  ptls_buffer_dispose(tcpls->sendbuf);
  ptls_buffer_dispose(tcpls->rec_reordering);
  free(tcpls->sendbuf);
  free(tcpls->recvbuf);
  free(tcpls->rec_reordering);
  heap_destroy(tcpls->priority_q);
  free(tcpls->priority_q);
  list_free(tcpls->streams);
  connect_info_t *con;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->buffrag) {
      ptls_buffer_dispose(con->buffrag);
      free(con->buffrag);
    }
    if (con->sendbuf) {
      ptls_buffer_dispose(con->sendbuf);
      free(con->sendbuf);
    }
  }
  list_free(tcpls->connect_infos);
  list_free(tcpls->cookies);
  ptls_tcpls_options_free(tcpls);
#define FREE_ADDR_LLIST(current, next) do {              \
  if (!next) {                                           \
    free(current);                                       \
  }                                                      \
  else {                                                 \
    while (next) {                                       \
      free(current);                                     \
      current = next;                                    \
      next = next->next;                                 \
    }                                                    \
  }                                                      \
} while(0);
  if (tcpls->v4_addr_llist) {
    tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
    tcpls_v4_addr_t *next = current->next;
    FREE_ADDR_LLIST(current, next);
  }
  if (tcpls->v6_addr_llist) {
    tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
    tcpls_v6_addr_t *next = current->next;
    FREE_ADDR_LLIST(current, next);
  }
  if (tcpls->ours_v4_addr_llist) {
    tcpls_v4_addr_t *current = tcpls->ours_v4_addr_llist;
    tcpls_v4_addr_t *next = tcpls->ours_v4_addr_llist->next;
    FREE_ADDR_LLIST(current, next);
  }
  if (tcpls->ours_v6_addr_llist) {
    tcpls_v6_addr_t *current = tcpls->ours_v6_addr_llist;
    tcpls_v6_addr_t *next = tcpls->ours_v6_addr_llist->next;
    FREE_ADDR_LLIST(current, next);
  }
#undef FREE_ADDR_LLIST
  ptls_free(tcpls->tls);
  free(tcpls);
}
