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

struct st_tcpls_record_fifo_t {
  int max_record_num;
  int size;
  uint8_t *queue;
  uint8_t *front;
  uint8_t *back;
  int front_idx;
  int back_idx;
};


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

void list_clean(list_t *list);

void list_free(list_t *list);

#endif
