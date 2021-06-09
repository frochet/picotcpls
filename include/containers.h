#ifndef containers_h
#define containers_h
#include "picotls.h"

struct st_list_t {
  int capacity;
  int size;
  int itemsize;
  uint8_t *items;
};

typedef enum queue_ret {
  OK,
  MEMORY_FULL,
  EMPTY
} queue_ret_t;

/** Used for failover to retain what sequence number and record length are
 * within our sending buffer */

struct st_tcpls_record_fifo_t {
  int max_record_num;
  int size;
  uint8_t *queue;
  uint8_t *front;
  uint8_t *back;
  int front_idx;
  int back_idx;
};

/* exposes a per-stream buffer abstraction to the application for the
 * multi-connection non-aggregation mode */

enum buf_kind {AGGREGATION, STREAMBASED};

struct st_tcpls_stream_buffer {
  ptls_buffer_t *decryptbuf;
  streamid_t streamid;
};

struct st_tcpls_buffer {
  enum buf_kind bufkind;
  union {
    struct { ptls_buffer_t *decryptbuf; };
    struct {
      list_t *stream_buffers;
      list_t *wtr_streams;
      /** we usually add streamid in order anyway. Try not to reorder if the
       * added value is greated than the max_streamid */
      streamid_t max_streamid;
    };
  };
};

/* create a tcpls_buffer_t* to use in a non-aggregated mode */
tcpls_buffer_t *tcpls_stream_buffers_new(tcpls_t *tcpls, int nbr_expected_streams);
/* create a tcpls_buffer_t* to use in aggregated mode */
tcpls_buffer_t *tcpls_aggr_buffer_new(tcpls_t *tcpls);

int tcpls_stream_buffer_add(tcpls_buffer_t *buffer, streamid_t streamid);

int tcpls_stream_buffer_remove(tcpls_buffer_t *buffer, streamid_t streamid);

/* should be O(log(n)) over a sorted array with sparse ids */
ptls_buffer_t *tcpls_get_stream_buffer(tcpls_buffer_t *buffer, streamid_t streamid);

void tcpls_buffer_free(tcpls_t *tcpls, tcpls_buffer_t *buf);

tcpls_record_fifo_t *tcpls_record_queue_new(int max_record_num);

queue_ret_t tcpls_record_queue_push(tcpls_record_fifo_t *fifo, uint32_t stream_seq, uint32_t reclen);

uint32_t tcpls_record_queue_seq(tcpls_record_fifo_t *queue);

queue_ret_t tcpls_record_queue_pop(tcpls_record_fifo_t *fifo, uint32_t *stream_seq, uint32_t *reclen);

queue_ret_t tcpls_record_queue_del(tcpls_record_fifo_t *fifo, int n);


void tcpls_record_fifo_free(tcpls_record_fifo_t *fifo);

list_t *new_list(int itemsize, int capacity);

int list_add(list_t *list, void *item);

void *list_get(list_t *list, int itemid);

int list_remove(list_t *list, void *item);

int list_contain(list_t *list, void *item);

void list_clean(list_t *list);

void list_free(list_t *list);

#endif
