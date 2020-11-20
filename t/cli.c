/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#if PICOTLS_USE_BROTLI
#include "brotli/decode.h"
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"
#if PICOTLS_USE_BROTLI
#include "picotls/certificate_compression.h"
#endif
#include "util.h"

/* sentinels indicating that the endpoint is in benchmark mode */
static const char input_file_is_benchmark[] = "is:benchmark";

static void shift_buffer(ptls_buffer_t *buf, size_t delta)
{
  if (delta != 0) {
    assert(delta <= buf->off);
    if (delta != buf->off)
      memmove(buf->base, buf->base + delta, buf->off - delta);
    buf->off -= delta;
  }
}

typedef enum integration_test_t {
  T_NOTEST,
  T_MULTIPATH,
  T_SIMPLE_HANDSHAKE,
  T_ZERO_RTT_HANDSHAKE
} integration_test_t;

struct tcpls_options {
  int timeoutval;
  unsigned int timeout;
  unsigned int is_second;
  list_t *our_addrs;
  list_t *our_addrs6;
  list_t *peer_addrs;
  list_t *peer_addrs6;
};

struct conn_to_tcpls {
  int conn_fd;
  int transportid;
  unsigned int is_primary : 1;
  streamid_t streamid;
  unsigned int wants_to_write : 1;
  tcpls_t *tcpls;
};

struct cli_data {
  list_t *socklist;
  list_t *streamlist;
};

static struct tcpls_options tcpls_options;

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
/** Simplistic joining procedure for testing */
static int handle_mpjoin(int socket, uint8_t *connid, uint8_t *cookie, uint32_t
    transportid, void *cbdata) {
  printf("Wooh, we're handling a mpjoin\n");
  list_t *conntcpls = (list_t*) cbdata;
  struct conn_to_tcpls *ctcpls;
  struct conn_to_tcpls *ctcpls2;
  for (int i = 0; i < conntcpls->size; i++) {
    ctcpls = list_get(conntcpls, i);
    if (!memcmp(ctcpls->tcpls->connid, connid, CONNID_LEN)) {
      for (int j = 0; j < conntcpls->size; j++) {
        ctcpls2 = list_get(conntcpls, j);
        if (ctcpls2->conn_fd == socket) {
          /*if (ctcpls2->tcpls)*/
            /*tcpls_free(ctcpls2->tcpls);*/
          ctcpls2->tcpls = ctcpls->tcpls;
        }
      }
      return tcpls_accept(ctcpls->tcpls, socket, cookie, transportid);
    }
  }
  return -1;
}

static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  switch (event) {
    case STREAM_OPENED:
      fprintf(stderr, "Handling stream_opened callback\n");
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_CLOSED:
      fprintf(stderr, "Handling stream_closed callback, removing stream %u\n", streamid);
      list_remove(data->streamlist, &streamid);
      break;
    default: break;
  }
  return 0;
}
static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
    streamid_t streamid, int transportid, void *cbdata) {
  list_t *conn_tcpls_l = (list_t *) cbdata;
  struct conn_to_tcpls *conn_tcpls;
  switch (event) {
    case STREAM_OPENED:
      fprintf(stderr, "Handling stream_opened callback\n");
      for (int i = 0; i < conn_tcpls_l->size; i++) {
        conn_tcpls = list_get(conn_tcpls_l, i);
        if (conn_tcpls->tcpls == tcpls && conn_tcpls->transportid == transportid) {
          fprintf(stderr, "Setting streamid %u as wants to write\n", streamid);
          conn_tcpls->streamid = streamid;
          conn_tcpls->is_primary = 1;
          conn_tcpls->wants_to_write = 1;
        }
      }
      break;
      /** currently assumes 2 streams */
    case STREAM_CLOSED:
      fprintf(stderr, "Handling stream_closed callback\n");
      for (int i = 0; i < conn_tcpls_l->size; i++) {
        conn_tcpls = list_get(conn_tcpls_l, i);
        if (conn_tcpls->transportid == transportid) {
          fprintf(stderr, "Woh! we're stopping to write on the connection linked to transportid %d\n", transportid);
          conn_tcpls->wants_to_write = 0;
          conn_tcpls->is_primary = 0;
        }
      }
    default: break;
  }
  return 0;
}

static int handle_client_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  switch (event) {
    case CONN_CLOSED:
      fprintf(stderr, "Received a CONN_CLOSED; removing the socket %d\n", socket);
      list_remove(data->socklist, &socket);
      break;
    case CONN_OPENED:
      fprintf(stderr, "Received a CONN_OPENED; adding the socket %d\n", socket);
      list_add(data->socklist, &socket);
      break;
    default: break;
  }
  return 0;
}

static int handle_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
  list_t *conntcpls = (list_t*) cbdata;
  switch (event) {
    case CONN_OPENED:
      {
        fprintf(stderr, "Received a CONN_OPENED; adding the socket\n");
        struct conn_to_tcpls *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->conn_fd == socket) {
            ctcpls->transportid = transportid;
            break;
          }
        }
      }
      break;
    case CONN_CLOSED:
      {
        fprintf(stderr, "Received a CONN_CLOSED; removing the socket\n");
        struct conn_to_tcpls *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->conn_fd == socket) {
            list_remove(conntcpls, ctcpls);
            break;
          }
        }
      }
      break;
    default: break;
  }
  return 0;
}

static void make_nonblocking(int fd)
{
  fcntl(fd, F_SETFL, O_NONBLOCK);
}

/** Temporaly to ease devopment. Later on: merge with handle_connection and make
 * TCPLS supports TLS 1.3's integration tests */

static void tcpls_add_ips(tcpls_t *tcpls, struct sockaddr_storage *sa_our,
    struct sockaddr_storage *sa_peer, int nbr_our, int nbr_peer) {
  int settopeer = tcpls->tls->is_server;
  for (int i = 0; i < nbr_our; i++) {
    if (sa_our[i].ss_family == AF_INET)
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_our[i], 1, settopeer, 1);
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_our[i], 0, settopeer, 1);
  }
  for (int i = 0; i < nbr_peer; i++) {
    if(sa_peer[i].ss_family == AF_INET)
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_peer[i], 1, 0, 0);
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_peer[i], 0, 0, 0);
  }
}
static int handle_tcpls_read(tcpls_t *tcpls, int socket) {

  int ret;
  if (!ptls_handshake_is_complete(tcpls->tls) && tcpls->tls->state <
      PTLS_STATE_SERVER_EXPECT_FINISHED) {
    ptls_handshake_properties_t prop = {NULL};
    memset(&prop, 0, sizeof(prop));
    prop.received_mpjoin_to_process = &handle_mpjoin;
    prop.socket = socket;
    if ((ret = tcpls_handshake(tcpls->tls, &prop)) != 0) {
      if (ret == PTLS_ERROR_HANDSHAKE_IS_MPJOIN) {
        return ret;
      }
      fprintf(stderr, "tcpls_handshake failed with ret %d\n", ret);
    }
    return 0;
  }
  ptls_buffer_t buf;
  ptls_buffer_init(&buf, "", 0);
  struct timeval timeout;
  memset(&timeout, 0, sizeof(timeout));
  while ((ret = tcpls_receive(tcpls->tls, &buf, &timeout)) == TCPLS_HOLD_DATA_TO_READ)
    ;
  if (ret < 0) {
    fprintf(stderr, "tcpls_receive returned %d\n",ret);
  }
  ret = buf.off;
  ptls_buffer_dispose(&buf);
  return ret;
}

static int handle_tcpls_write(tcpls_t *tcpls, struct conn_to_tcpls *conntotcpls,  int inputfd) {
  static const size_t block_size = 8192;
  uint8_t buf[block_size];
  int ret, ioret;
  while ((ioret = read(inputfd, buf, block_size)) == -1 && errno == EINTR)
    ;
  if (ioret > 0) {
    if((ret = tcpls_send(tcpls->tls, conntotcpls->streamid, buf, ioret)) < 0) {
      fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
          ret, conntotcpls->streamid);
      /*close(inputfd);*/
      /*inputfd = -1;*/
      return -1;
    }
    if (ret == TCPLS_HOLD_DATA_TO_SEND) {
      fprintf(stderr, "sending %d bytes on stream %u; not everything has been sent \n", ioret, conntotcpls->streamid);
    }
  } else if (ioret == 0) {
    /* closed */
    fprintf(stderr, "End-of-file, closing the connection linked to stream id\
        %u\n", conntotcpls->streamid);
    conntotcpls->wants_to_write = 0;
    return -2;
    close(inputfd);
    inputfd = -1;
  }
  else {
    perror("read failed");
    return -2;
  }
  /** continue */
  return 1;
}

static int handle_server_zero_rtt_test(list_t *conn_tcpls, fd_set *readset) {
  int ret = 1;
  for (int i = 0; i < conn_tcpls->size; i++) {
    struct conn_to_tcpls *conn = list_get(conn_tcpls, i);
    if (FD_ISSET(conn->conn_fd, readset)) {
      ret = handle_tcpls_read(conn->tcpls, conn->conn_fd);
      if (ptls_handshake_is_complete(conn->tcpls->tls))
        return 0;
      break;
    }
  }
  return ret;
}

static int handle_server_multipath_test(list_t *conn_tcpls, int inputfd, fd_set
    *readset, fd_set *writeset) {
  /** Now Read data for all tcpls_t * that wants to read */
  int ret = 1;
  for (int i = 0; i < conn_tcpls->size; i++) {
    struct conn_to_tcpls *conn = list_get(conn_tcpls, i);
    if (FD_ISSET(conn->conn_fd, readset)) {
      ret = handle_tcpls_read(conn->tcpls, conn->conn_fd);
      if (ptls_handshake_is_complete(conn->tcpls->tls) && conn->is_primary)
        conn->wants_to_write = 1;
      break;
    }
  }
  /** Write data for all tcpls_t * that wants to write :-) */
  for (int i = 0; i < conn_tcpls->size; i++) {
    struct conn_to_tcpls *conn = list_get(conn_tcpls, i);
    if (FD_ISSET(conn->conn_fd, writeset)) {
      /** Figure out the stream to send data */
      ret = handle_tcpls_write(conn->tcpls, conn, inputfd);
    }
  }
  return ret;
}

static int handle_client_multipath_test(tcpls_t *tcpls, struct cli_data *data) {
  /** handshake*/
  if (handle_tcpls_read(tcpls, 0) < 0)
    return -1;
  printf("Handshake done\n");
  fd_set readfds, writefds, exceptfds;
  int has_migrated = 0;
  int has_remigrated = 0;
  int received_data = 0;
  int mB_received = 0;
  struct timeval timeout;
  ptls_handshake_properties_t prop = {NULL};
  while (1) {
    int maxfds = 0;
    do {
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      FD_ZERO(&exceptfds);
      int *socket;
      for (int i = 0; i < data->socklist->size; i++) {
        socket = list_get(data->socklist, i);
        FD_SET(*socket, &readfds);
        if (maxfds <= *socket)
          maxfds = *socket;
      }
      timeout.tv_sec = 3600;
      timeout.tv_usec = 0;
    } while (select(maxfds+1, &readfds, &writefds, &exceptfds, &timeout) == -1);

    int ret;
    int *socket;
    for (int i = 0; i < data->socklist->size; i++) {
      socket = list_get(data->socklist, i);
      if (FD_ISSET(*socket, &readfds)) {
        if ((ret = handle_tcpls_read(tcpls, *socket)) < 0) {
          fprintf(stderr, "handle_tcpls_read returned %d\n",ret);
          break;
        }
        received_data += ret;
        if (received_data / 1000000 > mB_received) {
          mB_received++;
          printf("Received %d MB\n",mB_received);
        }
        break;
      }
    }
    if (received_data >= 41457280  && !has_remigrated) {
      has_remigrated = 1;
      /*struct timeval timeout;*/
      /*timeout.tv_sec = 5;*/
      /*timeout.tv_usec = 0;*/
      /*tcpls_connect(tcpls->tls, NULL, (struct sockaddr*) &tcpls->v4_addr_llist->addr, &timeout, -1);*/
      /*int socket = 0;*/
      connect_info_t *con = NULL;
      for (int i = 0; i < tcpls->connect_infos->size; i++) {
        con = list_get(tcpls->connect_infos, i);
        if (con->dest) {
          break;
        }
      }
      prop.client.transportid = con->this_transportid;
      prop.client.mpjoin = 1;
      prop.client.zero_rtt = 1;
      prop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
      int ret = tcpls_handshake(tcpls->tls, &prop);
      if (!ret) {
        tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
            &tcpls->v4_addr_llist->addr);
        tcpls_streams_attach(tcpls->tls, 0, 1);
        /** closing the stream id 1 */
        tcpls_stream_close(tcpls->tls, 1, 1);
      }
      else {
        fprintf(stderr, "tcpls_handshake returned %d\n", ret);
        return -1;
      }
    }
    /** We test a migration */
    if (received_data >= 21457280 && !has_migrated) {
      has_migrated = 1;
      int socket = 0;
      connect_info_t *con = NULL;
      for (int i = 0; i < tcpls->connect_infos->size; i++) {
        con = list_get(tcpls->connect_infos, i);
        if (con->dest6) {
          socket = con->socket;
          break;
        }
      }
      prop.socket = socket;
      prop.client.transportid = con->this_transportid;
      prop.client.mpjoin = 1;
      /** Make a tcpls mpjoin handshake */
      int ret;

      ret = tcpls_handshake(tcpls->tls, &prop);
      if (!ret) {
        /** Create a stream on the new connection */
        tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
            &tcpls->v6_addr_llist->addr);
        tcpls_streams_attach(tcpls->tls, 0, 1);
        /** Close the stream on the initial connection */
        streamid_t *streamid2 = list_get(data->streamlist, 0);
        tcpls_stream_close(tcpls->tls, *streamid2, 1);
      }
    }
  }
  return 0;
}

static int handle_client_simple_handshake(tcpls_t *tcpls, struct cli_data *data) {
  int ret;
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  struct timeval t_init, t_now;
  gettimeofday(&t_init, NULL);
  int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout, -1);
  if (err){
    fprintf(stderr, "tcpls_connect failed with err %d\n", err);
    return 1;
  }
  ptls_handshake_properties_t prop = {NULL};
  prop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
  ret = tcpls_handshake(tcpls->tls, &prop);
  gettimeofday(&t_now, NULL);
  struct timeval rtt = timediff(&t_now, &t_init);
  printf("Handshake took %lu µs\n", rtt.tv_sec*1000000+rtt.tv_usec);
  return ret;
}

static int handle_client_zero_rtt_test(tcpls_t *tcpls, struct cli_data *data) {
  int ret;
  ptls_handshake_properties_t prop = {NULL};
  prop.client.zero_rtt = 1;
  if (tcpls->v4_addr_llist)
    prop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
  else
    prop.client.dest = (struct sockaddr_storage *) &tcpls->v6_addr_llist->addr;
  struct timeval t_init, t_now;
  gettimeofday(&t_init, NULL);
  ret = tcpls_handshake(tcpls->tls, &prop);
  gettimeofday(&t_now, NULL);
  struct timeval rtt = timediff(&t_now, &t_init);
  printf("Handshake took %lu µs\n", rtt.tv_sec*1000000+rtt.tv_usec);
  return ret;
}

static int handle_client_connection(tcpls_t *tcpls, struct cli_data *data,
    integration_test_t test) {
  int ret;
  switch (test) {
    case T_SIMPLE_HANDSHAKE:
      ret = handle_client_simple_handshake(tcpls, data);
      if (!ret)
        printf("TEST Simple Handshake: SUCCESS\n");
      else
        printf("TEST Simple Handshake: FAILURE\n");
      break;
    case T_ZERO_RTT_HANDSHAKE:
      ret = handle_client_zero_rtt_test(tcpls, data);
      if (!ret)
        printf("TEST 0-RTT: SUCCESS\n");
      else
        printf("TEST 0-RTT: FAILURE\n");
      break;
    case T_MULTIPATH:
      {
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout, -1);
        if (err){
          fprintf(stderr, "tcpls_connect failed with err %d\n", err);
          return 1;
        }
        ret = handle_client_multipath_test(tcpls, data);
        if (!ret)
          printf("TEST MULTIPATH: SUCCESS\n");
        else
          printf("TEST MULTIPATH: FAILURE\n");
      }
      break;
    case T_NOTEST:
      printf("NO TEST");
      exit(1);
  }
  return 0;
}

static int handle_connection(int sockfd, ptls_context_t *ctx, const char *server_name, const char *input_file,
    ptls_handshake_properties_t *hsprop, int request_key_update, int keep_sender_open)
{
  static const int inputfd_is_benchmark = -2;

  ptls_t *tls = ptls_new(ctx, server_name == NULL);
  ptls_buffer_t rbuf, encbuf, ptbuf;
  enum { IN_HANDSHAKE, IN_1RTT, IN_SHUTDOWN } state = IN_HANDSHAKE;
  int inputfd = 0, ret = 0;
  size_t early_bytes_sent = 0;
  uint64_t data_received = 0;
  ssize_t ioret;

  uint64_t start_at = ctx->get_time->cb(ctx->get_time);

  ptls_buffer_init(&rbuf, "", 0);
  ptls_buffer_init(&encbuf, "", 0);
  ptls_buffer_init(&ptbuf, "", 0);


  fcntl(sockfd, F_SETFL, O_NONBLOCK);

  if (input_file == input_file_is_benchmark) {
    if (!ptls_is_server(tls))
      inputfd = inputfd_is_benchmark;
  } else if (input_file != NULL) {
    if ((inputfd = open(input_file, O_RDONLY)) == -1) {
      fprintf(stderr, "failed to open file:%s:%s\n", input_file, strerror(errno));
      ret = 1;
      goto Exit;
    }
  }
  if (server_name != NULL) {
    ptls_set_server_name(tls, server_name, 0);
    if ((ret = ptls_handshake(tls, &encbuf, NULL, NULL, hsprop)) != PTLS_ERROR_IN_PROGRESS) {
      fprintf(stderr, "ptls_handshake:%d\n", ret);
      ret = 1;
      goto Exit;
    }
  }


  while (1) {
    /* check if data is available */
    fd_set readfds, writefds, exceptfds;
    int maxfd = 0;
    struct timeval timeout;

    do {
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      FD_ZERO(&exceptfds);
      FD_SET(sockfd, &readfds);
      if (encbuf.off != 0 || inputfd == inputfd_is_benchmark)
        FD_SET(sockfd, &writefds);
      FD_SET(sockfd, &exceptfds);
      maxfd = sockfd + 1;
      if (inputfd >= 0) {
        FD_SET(inputfd, &readfds);
        FD_SET(inputfd, &exceptfds);
        if (maxfd <= inputfd)
          maxfd = inputfd + 1;
      }
      timeout.tv_sec = encbuf.off != 0 ? 0 : 3600;
      timeout.tv_usec = 0;
    } while (select(maxfd, &readfds, &writefds, &exceptfds, &timeout) == -1);


    /* consume incoming messages */
    if (FD_ISSET(sockfd, &readfds) || FD_ISSET(sockfd, &exceptfds)) {
      char bytebuf[16384];
      size_t off = 0, leftlen;
      while ((ioret = read(sockfd, bytebuf, sizeof(bytebuf))) == -1 && errno == EINTR)
        ;
      if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        /* no data */
        ioret = 0;
      } else if (ioret <= 0) {
        goto Exit;
      }
      while ((leftlen = ioret - off) != 0) {
        if (state == IN_HANDSHAKE) {
          if ((ret = ptls_handshake(tls, &encbuf, bytebuf + off, &leftlen, hsprop)) == 0) {
            state = IN_1RTT;
            assert(ptls_is_server(tls) || hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
            /* release data sent as early-data, if server accepted it */
            if (hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
              shift_buffer(&ptbuf, early_bytes_sent);
            if (request_key_update)
              ptls_update_key(tls, 1);
          } else if (ret == PTLS_ERROR_IN_PROGRESS) {
            /* ok */
          } else {
            if (encbuf.off != 0)
              (void)write(sockfd, encbuf.base, encbuf.off);
            fprintf(stderr, "ptls_handshake:%d\n", ret);
            goto Exit;
          }
        } else {
          if ((ret = ptls_receive(tls, &rbuf, NULL, bytebuf + off, &leftlen)) == 0) {
            if (rbuf.off != 0) {
              data_received += rbuf.off;
              if (input_file != input_file_is_benchmark)
                write(1, rbuf.base, rbuf.off);
              rbuf.off = 0;
            }
          } else if (ret == PTLS_ERROR_IN_PROGRESS) {
            /* ok */
          } else {
            fprintf(stderr, "ptls_receive:%d\n", ret);
            goto Exit;
          }
        }
        off += leftlen;
      }
    }


    /* encrypt data to send, if any is available */
    if (encbuf.off == 0 || state == IN_HANDSHAKE) {
      static const size_t block_size = 16384;
      if (inputfd >= 0 && (FD_ISSET(inputfd, &readfds) || FD_ISSET(inputfd, &exceptfds))) {
        if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
          goto Exit;
        while ((ioret = read(inputfd, ptbuf.base + ptbuf.off, block_size)) == -1 && errno == EINTR)
          ;
        if (ioret > 0) {
          ptbuf.off += ioret;
        } else if (ioret == 0) {
          /* closed */
          if (input_file != NULL)
            close(inputfd);
          inputfd = -1;
        }
      } else if (inputfd == inputfd_is_benchmark) {
        if (ptbuf.capacity < block_size) {
          if ((ret = ptls_buffer_reserve(&ptbuf, block_size - ptbuf.capacity)) != 0)
            goto Exit;
          memset(ptbuf.base + ptbuf.capacity, 0, block_size - ptbuf.capacity);
        }
        ptbuf.off = block_size;
      }
    }
    if (ptbuf.off != 0) {
      if (state == IN_HANDSHAKE) {
        size_t send_amount = 0;
        if (server_name != NULL && hsprop->client.max_early_data_size != NULL) {
          size_t max_can_be_sent = *hsprop->client.max_early_data_size;
          if (max_can_be_sent > ptbuf.off)
            max_can_be_sent = ptbuf.off;
          send_amount = max_can_be_sent - early_bytes_sent;
        }
        if (send_amount != 0) {
          if ((ret = ptls_send(tls, &encbuf, ptbuf.base, send_amount)) != 0) {
            fprintf(stderr, "ptls_send(early_data):%d\n", ret);
            goto Exit;
          }
          early_bytes_sent += send_amount;
        }
      } else {
        if ((ret = ptls_send(tls, &encbuf, ptbuf.base, ptbuf.off)) != 0) {
          fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
          goto Exit;
        }
        ptbuf.off = 0;
      }
    }

    /* send any data */
    if (encbuf.off != 0) {
      while ((ioret = write(sockfd, encbuf.base, encbuf.off)) == -1 && errno == EINTR)
        ;
      if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        /* no data */
      } else if (ioret <= 0) {
        goto Exit;
      } else {
        shift_buffer(&encbuf, ioret);
      }
    }

    /* close the sender side when necessary */
    if (state == IN_1RTT && inputfd == -1) {
      if (!keep_sender_open) {
        ptls_buffer_t wbuf;
        uint8_t wbuf_small[32];
        ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
        if ((ret = ptls_send_alert(tls, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
          fprintf(stderr, "ptls_send_alert:%d\n", ret);
        }
        if (wbuf.off != 0)
          (void)write(sockfd, wbuf.base, wbuf.off);
        ptls_buffer_dispose(&wbuf);
        shutdown(sockfd, SHUT_WR);
      }
      state = IN_SHUTDOWN;
    }
  }

Exit:
  if (input_file == input_file_is_benchmark) {
    double elapsed = (ctx->get_time->cb(ctx->get_time) - start_at) / 1000.0;
    ptls_cipher_suite_t *cipher_suite = ptls_get_cipher(tls);
    fprintf(stderr, "received %" PRIu64 " bytes in %.3f seconds (%f.3Mbps); %s\n", data_received, elapsed,
        data_received * 8 / elapsed / 1000 / 1000, cipher_suite != NULL ? cipher_suite->aead->name : "unknown cipher");
  }

  if (sockfd != -1)
    close(sockfd);
  if (input_file != NULL && input_file != input_file_is_benchmark && inputfd >= 0)
    close(inputfd);
  ptls_buffer_dispose(&rbuf);
  ptls_buffer_dispose(&encbuf);
  ptls_buffer_dispose(&ptbuf);
  ptls_free(tls);
  return ret != 0;
}

static int run_server(struct sockaddr_storage *sa_ours, struct sockaddr_storage
    *sa_peers, int nbr_ours, int nbr_peers, ptls_context_t *ctx, const char *input_file,
    ptls_handshake_properties_t *hsprop, int request_key_update, integration_test_t test)
{
  int conn_fd, on = 1;
  int inputfd = 0;
  int listenfd[nbr_ours];
  list_t *conn_tcpls = new_list(sizeof(struct conn_to_tcpls), 2);
  ctx->connection_event_cb = &handle_connection_event;
  ctx->stream_event_cb = &handle_stream_event;
  ctx->cb_data = conn_tcpls;
  socklen_t salen;
  struct timeval timeout;
  ctx->output_decrypted_tcpls_data = 0;
  list_t *tcpls_l = new_list(sizeof(tcpls_t *),2);
  memset(&timeout, 0, sizeof(struct timeval));
  int qlen = 5;
  for (int i = 0; i < nbr_ours; i++) {
    if (sa_ours[i].ss_family == AF_INET) {
      if ((listenfd[i] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return 1;
      }
    }
    else if (sa_ours[i].ss_family == AF_INET6) {
      if ((listenfd[i] = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return 1;
      }
    }
    if (setsockopt(listenfd[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
      perror("setsockopt(SO_REUSEADDR) failed");
      return 1;
    }
    if (setsockopt(listenfd[i], SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0) {
      perror("setsockopt(TCP_FASTOPEN) failed");
    }
    if (sa_ours[i].ss_family == AF_INET)
      salen = sizeof(struct sockaddr_in);
    else
      salen = sizeof(struct sockaddr_in6);

    if (bind(listenfd[i], (struct sockaddr*) &sa_ours[i], salen) != 0) {
      perror("bind(2) failed");
      return 1;
    }

    if (listen(listenfd[i], SOMAXCONN) != 0) {
      perror("listen(2) failed");
      return 1;
    }
    /** For now, tcpls tests require nonblocking sockets compared to initial TLS
     * tests*/
    if (ctx->support_tcpls_options) {
      make_nonblocking(listenfd[i]);
    }
  }

  if (ctx->support_tcpls_options) {
    while (1) {
      /*sleep(1);*/
      fd_set readset, writeset;
      int maxfd = 0;
      do {
        timeout.tv_sec = 100;
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        /** put all listeners in the read set */
        for (int i = 0; i < nbr_ours; i++) {
          FD_SET(listenfd[i], &readset);
          if (maxfd < listenfd[i])
            maxfd = listenfd[i];
        }
        /** put all tcpls connections within the read set, and the write set if
         * they want to write */
        for (int i = 0; i < conn_tcpls->size; i++) {
          struct conn_to_tcpls *conn = list_get(conn_tcpls, i);
          FD_SET(conn->conn_fd, &readset);
          if (conn->wants_to_write)
            FD_SET(conn->conn_fd, &writeset);
          if (maxfd < conn->conn_fd)
            maxfd = conn->conn_fd;
        }
        /*fprintf(stderr, "waiting for connection or r/w event...\n");*/
      } while (select(maxfd+1, &readset, &writeset, NULL, &timeout) == -1);
      /** Check first we have a listen() connection */
      for (int i = 0; i < nbr_ours; i++) {
        if (FD_ISSET(listenfd[i], &readset)) {
          struct sockaddr_storage ss;
          socklen_t slen = sizeof(ss);
          int new_conn = accept(listenfd[i], (struct sockaddr *)&ss, &slen);
          if (new_conn < 0) {
            perror("accept");
          }
          else if (new_conn > FD_SETSIZE)
            close(new_conn);
          else {
            fprintf(stderr, "Accepting a new connection\n");
            tcpls_t *new_tcpls = tcpls_new(ctx,  1);
            struct conn_to_tcpls conntcpls;
            memset(&conntcpls, 0, sizeof(conntcpls));
            conntcpls.conn_fd = new_conn;
            conntcpls.wants_to_write = 0;
            conntcpls.tcpls = new_tcpls;
            list_add(tcpls_l, new_tcpls);
            /** ADD our ips  -- This might worth to be ctx and instance-based?*/
            tcpls_add_ips(new_tcpls, sa_ours, NULL, nbr_ours, 0);
            if (conn_tcpls->size == 0)
              conntcpls.is_primary = 1;
            list_add(conn_tcpls, &conntcpls);
            if (tcpls_accept(new_tcpls, conntcpls.conn_fd, NULL, 0) < 0)
              fprintf(stderr, "tcpls_accept returned -1\n");
          }
        }
      }
      int ret;
      switch (test) {
        case T_MULTIPATH:
          assert(input_file);
          if (!inputfd && (inputfd = open(input_file, O_RDONLY)) == -1) {
            fprintf(stderr, "failed to open file:%s:%s\n", input_file, strerror(errno));
            goto Exit;
          }
          if ((ret = handle_server_multipath_test(conn_tcpls, inputfd,  &readset, &writeset)) < -1) {
            goto Exit;
          }
          break;
        case T_ZERO_RTT_HANDSHAKE:
        case T_SIMPLE_HANDSHAKE:
          if ((ret = handle_server_zero_rtt_test(conn_tcpls, &readset)) < 0) {
            goto Exit;
          }
          break;
        case T_NOTEST:
          exit(0);
      }
    }
  }
  else {
    while (1) {
      fprintf(stderr, "waiting for connections\n");
      if ((conn_fd = accept(listenfd[0], NULL, 0)) != -1) {
        handle_connection(conn_fd, ctx, NULL, input_file, hsprop, request_key_update, 0);
      }
    }
  }
  for (int i = 0; i < tcpls_l->size; i++) {
    tcpls_t *tcpls = list_get(tcpls_l, i);
    tcpls_free(tcpls);
  }
  list_free(conn_tcpls);
  return 0;
Exit:
  list_free(conn_tcpls);
  exit(0);
}

static int run_client(struct sockaddr_storage *sa_our, struct sockaddr_storage
    *sa_peer, int nbr_our, int nbr_peer,  ptls_context_t *ctx, const char *server_name, const char
    *input_file, ptls_handshake_properties_t *hsprop, int request_key_update,
    int keep_sender_open, integration_test_t test)
{
  int fd;

  hsprop->client.esni_keys = resolve_esni_keys(server_name);
  list_t *socklist = new_list(sizeof(int), 2);
  list_t *streamlist = new_list(sizeof(tcpls_stream_t), 2);
  struct cli_data data = {NULL};
  data.socklist = socklist;
  data.streamlist = streamlist;
  ctx->cb_data = &data;
  ctx->stream_event_cb = &handle_client_stream_event;
  ctx->connection_event_cb = &handle_client_connection_event;
  tcpls_t *tcpls = tcpls_new(ctx, 0);
  tcpls_add_ips(tcpls, sa_our, sa_peer, nbr_our, nbr_peer);
  ctx->output_decrypted_tcpls_data = 0;


  if (ctx->support_tcpls_options) {
    int ret = handle_client_connection(tcpls, &data, test);
    free(hsprop->client.esni_keys.base);
    tcpls_free(tcpls);
    return ret;
  }
  else {
    struct timeval timeout = {.tv_sec = 100, .tv_usec = 0};
    int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout, -1);
    if (err){
      fprintf(stderr, "tcpls_connect failed with err %d\n", err);
      return 1;
    }
    fd = tcpls->socket_primary;
    int ret = handle_connection(fd, ctx, server_name, input_file, hsprop, request_key_update, keep_sender_open);
    free(hsprop->client.esni_keys.base);
    tcpls_free(tcpls);
    return ret;
  }
}

static void usage(const char *cmd)
{
  printf("Usage: %s [options] host port\n"
      "\n"
      "Options:\n"
      "  -4                   force IPv4\n"
      "  -6                   force IPv6\n"
      "  -a                   require client authentication\n"
      "  -b                   enable brotli compression\n"
      "  -B                   benchmark mode for measuring sustained bandwidth. Run\n"
      "                       both endpoints with this option for some time, then kill\n"
      "                       the client. Server will report the ingress bandwidth.\n"
      "  -C certificate-file  certificate chain used for client authentication\n"
      "  -c certificate-file  certificate chain used for server authentication\n"
      "  -i file              a file to read from and send to the peer (default: stdin)\n"
      "  -I                   keep send side open after sending all data (client-only)\n"
      "  -k key-file          specifies the credentials for signing the certificate\n"
      "  -l log-file          file to log events (incl. traffic secrets)\n"
      "  -n                   negotiates the key exchange method (i.e. wait for HRR)\n"
      "  -N named-group       named group to be used (default: secp256r1)\n"
      "  -s session-file      file to read/write the session ticket\n"
      "  -S                   require public key exchange when resuming a session\n"
      "  -E esni-file         file that stores ESNI data generated by picotls-esni\n"
      "  -e                   when resuming a session, send first 8,192 bytes of input\n"
      "                       as early data\n"
      "  -u                   update the traffic key when handshake is complete\n"
      "  -v                   verify peer using the default certificates\n"
      "  -y cipher-suite      cipher-suite to be used, e.g., aes128gcmsha256 (default:\n"
      "                       all)\n"
      "  -h                   print this help\n"
      "  -t                   Use tcpls\n"
      "  -T intergration_test Precise which integration test is to be run\n"
      "\n"
      "Supported named groups: secp256r1"
#if PTLS_OPENSSL_HAVE_SECP384R1
      ", secp384r1"
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
      ", secp521r1"
#endif
#if PTLS_OPENSSL_HAVE_X25519
      ", X25519"
#endif
      "\n\n",
    cmd);
}

int main(int argc, char **argv)
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
  /* Load all compiled-in ENGINEs */
  ENGINE_load_builtin_engines();
  ENGINE_register_all_ciphers();
  ENGINE_register_all_digests();
#endif

  res_init();

  ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
  ptls_cipher_suite_t *cipher_suites[128] = {NULL};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};
  ptls_handshake_properties_t hsprop = {{{{NULL}}}};
  const char *host, *port, *input_file = NULL, *esni_file = NULL;
  integration_test_t test = T_NOTEST;
  struct {
    ptls_key_exchange_context_t *elements[16];
    size_t count;
  } esni_key_exchanges;
  int is_server = 0, use_early_data = 0, request_key_update = 0, keep_sender_open = 0, ch;
  /*struct sockaddr_storage sa;*/
  socklen_t salen;
  memset(&tcpls_options, 0, sizeof(tcpls_options));
  tcpls_options.our_addrs = new_list(15*sizeof(char), 2);
  tcpls_options.peer_addrs = new_list(15*sizeof(char), 2);
  tcpls_options.our_addrs6 = new_list(39*sizeof(char), 2);
  tcpls_options.peer_addrs6 = new_list(39*sizeof(char), 2);
  int family = 0;

  while ((ch = getopt(argc, argv, "46abBC:c:i:Ik:nN:es:SE:K:l:y:vhtd:p:P:z:Z:T:")) != -1) {
    switch (ch) {
      case '4':
        family = AF_INET;
        break;
      case '6':
        family = AF_INET6;
        break;
      case 'a':
        ctx.require_client_authentication = 1;
        break;
      case 'b':
#if PICOTLS_USE_BROTLI
        ctx.decompress_certificate = &ptls_decompress_certificate;
#else
        fprintf(stderr, "support for `-b` option was turned off during configuration\n");
        exit(1);
#endif
        break;
      case 'B':
        input_file = input_file_is_benchmark;
        break;
      case 'C':
      case 'c':
        if (ctx.certificates.count != 0) {
          fprintf(stderr, "-C/-c can only be specified once\n");
          return 1;
        }
        load_certificate_chain(&ctx, optarg);
        is_server = ch == 'c';
        break;
      case 'i':
        input_file = optarg;
        break;
      case 'I':
        keep_sender_open = 1;
        break;
      case 'k':
        load_private_key(&ctx, optarg);
        break;
      case 'n':
        hsprop.client.negotiate_before_key_exchange = 1;
        break;
      case 'e':
        use_early_data = 1;
        break;
      case 's':
        setup_session_file(&ctx, &hsprop, optarg);
        break;
      case 'S':
        ctx.require_dhe_on_psk = 1;
        break;
      case 'E':
        esni_file = optarg;
        break;
      case 'K': {
                  FILE *fp;
                  EVP_PKEY *pkey;
                  int ret;
                  if ((fp = fopen(optarg, "rt")) == NULL) {
                    fprintf(stderr, "failed to open ESNI private key file:%s:%s\n", optarg, strerror(errno));
                    return 1;
                  }
                  if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
                    fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                    return 1;
                  }
                  if ((ret = ptls_openssl_create_key_exchange(esni_key_exchanges.elements + esni_key_exchanges.count++, pkey)) != 0) {
                    fprintf(stderr, "failed to load private key from file:%s:picotls-error:%d", optarg, ret);
                    return 1;
                  }
                  EVP_PKEY_free(pkey);
                  fclose(fp);
                } break;
      case 'l':
                setup_log_event(&ctx, optarg);
                break;
      case 'v':
                setup_verify_certificate(&ctx);
                break;
      case 'N': {
                  ptls_key_exchange_algorithm_t *algo = NULL;
#define MATCH(name)                                                                                                                \
                  if (algo == NULL && strcasecmp(optarg, #name) == 0)                                                                            \
                  algo = (&ptls_openssl_##name)
                  MATCH(secp256r1);
#if PTLS_OPENSSL_HAVE_SECP384R1
                  MATCH(secp384r1);
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
                  MATCH(secp521r1);
#endif
#if PTLS_OPENSSL_HAVE_X25519
                  MATCH(x25519);
#endif
#undef MATCH
                  if (algo == NULL) {
                    fprintf(stderr, "could not find key exchange: %s\n", optarg);
                    return 1;
                  }
                  size_t i;
                  for (i = 0; key_exchanges[i] != NULL; ++i)
                    ;
                  key_exchanges[i++] = algo;
                } break;
      case 'u':
                request_key_update = 1;
                break;
      case 'y': {
                  size_t i;
                  for (i = 0; cipher_suites[i] != NULL; ++i)
                    ;
#define MATCH(name)                                                                                                                \
                  if (cipher_suites[i] == NULL && strcasecmp(optarg, #name) == 0)                                                                \
                  cipher_suites[i] = &ptls_openssl_##name
                  MATCH(aes128gcmsha256);
                  MATCH(aes256gcmsha384);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
                  MATCH(chacha20poly1305sha256);
#endif
#undef MATCH
                  if (cipher_suites[i] == NULL) {
                    fprintf(stderr, "unknown cipher-suite: %s\n", optarg);
                    exit(1);
                  }
                } break;
      case 'T':
                if (strcasecmp(optarg, "multipath") == 0)
                  test = T_MULTIPATH;
                else if (strcasecmp(optarg, "zero_rtt") == 0)
                  test = T_ZERO_RTT_HANDSHAKE;
                else if (strcasecmp(optarg, "simple_handshake") == 0)
                  test = T_SIMPLE_HANDSHAKE;
                else {
                  fprintf(stderr, "Unknown integration test: %s\n", optarg);
                  exit(1);
                }
                break;

      case 'h':
                usage(argv[0]);
                exit(0);
      case 't':
                ctx.support_tcpls_options = 1;
                break;


      case 'd':
                if(sscanf(optarg, "%d %d", &tcpls_options.timeoutval, &tcpls_options.is_second) < 0){
                  usage(argv[0]);
                  exit(0);
                }
                tcpls_options.timeout = 1;
                break;
      case 'p':
                {
                  char addr[16];
                  if (strlen(optarg) > 15)  {
                    fprintf(stderr, "Uncorrect v4 addr: %s\n", optarg);
                    exit(1);
                  }
                  if (!tcpls_options.peer_addrs)
                    tcpls_options.peer_addrs = new_list(16*sizeof(char), 2);
                  memcpy(addr, optarg, strlen(optarg));
                  addr[strlen(optarg)] = '\0';
                  list_add(tcpls_options.peer_addrs, addr);
                }
                break;
      case 'P':
                {
                  char addr6[40];
                  if (strlen(optarg) > 39)  {
                    fprintf(stderr, "Uncorrect v6 addr: %s\n", optarg);
                    exit(1);
                  }
                  if (!tcpls_options.peer_addrs)
                    tcpls_options.peer_addrs6 = new_list(40*sizeof(char), 2);
                  memcpy(addr6, optarg, strlen(optarg));
                  addr6[strlen(optarg)] = '\0';
                  list_add(tcpls_options.peer_addrs6, addr6);
                }
                break;

      case 'z':
                {
                  char addr[16];
                  if (strlen(optarg) > 15)  {
                    fprintf(stderr, "Uncorrect v4 addr: %s\n", optarg);
                    exit(1);
                  }
                  if (!tcpls_options.our_addrs)
                    tcpls_options.our_addrs = new_list(16*sizeof(char), 2);
                  memcpy(addr, optarg, strlen(optarg));
                  addr[strlen(optarg)] = '\0';
                  list_add(tcpls_options.our_addrs, addr);
                }
                break;
      case 'Z':
                {
                  char addr6[40];
                  if (strlen(optarg) > 39)  {
                    fprintf(stderr, "Uncorrect v6 addr: %s\n", optarg);
                    exit(1);
                  }
                  if (!tcpls_options.our_addrs6)
                    tcpls_options.our_addrs6 = new_list(40*sizeof(char), 2);
                  memcpy(addr6, optarg, strlen(optarg));
                  addr6[strlen(optarg)] = '\0';
                  list_add(tcpls_options.our_addrs6, addr6);
                }
                break;
      default:
                exit(1);
    }
  }
  argc -= optind;
  argv += optind;
  if ((ctx.certificates.count == 0) != (ctx.sign_certificate == NULL)) {
    fprintf(stderr, "-C/-c and -k options must be used together\n");
    return 1;
  }
  if (is_server) {
    if (ctx.certificates.count == 0) {
      fprintf(stderr, "-c and -k options must be set\n");
      return 1;
    }
#if PICOTLS_USE_BROTLI
    if (ctx.decompress_certificate != NULL) {
      static ptls_emit_compressed_certificate_t ecc;
      if (ptls_init_compressed_certificate(&ecc, ctx.certificates.list, ctx.certificates.count, ptls_iovec_init(NULL, 0)) !=
          0) {
        fprintf(stderr, "failed to create a brotli-compressed version of the certificate chain.\n");
        exit(1);
      }
      ctx.emit_certificate = &ecc.super;
    }
#endif
    setup_session_cache(&ctx);
  } else {
    /* client */
    if (use_early_data) {
      static size_t max_early_data_size;
      hsprop.client.max_early_data_size = &max_early_data_size;
    }
    ctx.send_change_cipher_spec = 1;
  }
  if (key_exchanges[0] == NULL)
    key_exchanges[0] = &ptls_openssl_secp256r1;
  if (cipher_suites[0] == NULL) {
    size_t i;
    for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
      cipher_suites[i] = ptls_openssl_cipher_suites[i];
  }
  if (esni_file != NULL) {
    if (esni_key_exchanges.count == 0) {
      fprintf(stderr, "-E must be used together with -K\n");
      return 1;
    }
    setup_esni(&ctx, esni_file, esni_key_exchanges.elements);
  }
  if (argc != 2) {
    fprintf(stderr, "missing host and port\n");
    return 1;
  }
  host = (--argc, *argv++);
  port = (--argc, *argv++);
  int nbr_our_addrs, nbr_peer_addrs, offset;
  offset = 0;
  if (is_server) {
    nbr_our_addrs = tcpls_options.our_addrs->size + tcpls_options.our_addrs6->size + 1;
    nbr_peer_addrs = tcpls_options.peer_addrs->size + tcpls_options.peer_addrs6->size;
  }
  else {
    nbr_our_addrs = tcpls_options.our_addrs->size + tcpls_options.our_addrs6->size;
    nbr_peer_addrs = tcpls_options.peer_addrs->size + tcpls_options.peer_addrs6->size+1;
  }
  struct sockaddr_storage sa_ours[nbr_our_addrs];
  struct sockaddr_storage sa_peer[nbr_peer_addrs];

  char *addr;
  for (int i = 0; i < tcpls_options.our_addrs->size; i++) {
    addr = list_get(tcpls_options.our_addrs, i);
    if (resolve_address((struct sockaddr *)&sa_ours[i], &salen, addr, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }
  offset += tcpls_options.our_addrs->size;
  for (int i = 0; i < tcpls_options.our_addrs6->size; i++) {
    addr = list_get(tcpls_options.our_addrs6, i);
    if (resolve_address((struct sockaddr *)&sa_ours[i+offset], &salen, addr, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }
  offset = 0;
  for (int i = 0; i < tcpls_options.peer_addrs->size; i++) {
    addr = list_get(tcpls_options.peer_addrs, i);
    if (resolve_address((struct sockaddr *)&sa_peer[i], &salen, addr, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }
  offset += tcpls_options.peer_addrs->size;
  for (int i = 0; i < tcpls_options.peer_addrs6->size; i++) {
    addr = list_get(tcpls_options.peer_addrs6, i);
    if (resolve_address((struct sockaddr *)&sa_peer[i+offset], &salen, addr, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }
  /**  resolve the host line -- keep it for backward compatibility */
  struct sockaddr *sockaddr_ptr;
  if (is_server) {
    sockaddr_ptr = (struct sockaddr*) &sa_ours[nbr_our_addrs-1];
  }
  else {
    sockaddr_ptr = (struct sockaddr*) &sa_peer[nbr_peer_addrs-1];
  }
  if (resolve_address(sockaddr_ptr, &salen, host, port,
        family, SOCK_STREAM, IPPROTO_TCP) != 0) 
    exit(1);


  if (is_server) {
    return run_server(sa_ours, sa_peer, nbr_our_addrs, nbr_peer_addrs, &ctx,
        input_file, &hsprop, request_key_update, test);
  } else {
    return run_client(sa_ours, sa_peer, nbr_our_addrs, nbr_peer_addrs, &ctx,
        host, input_file, &hsprop, request_key_update, keep_sender_open, test);
  }
}
