#include "containers.h"
#include "picotls.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ===========================FIFO======================================= */

/**
 * FIFO queue of max_record_num (cannot be extended). If the buffer is full,
 * no more records can be send with TCPLS, and we need to wait for
 * acknowledgments to arrive to free space
 */

tcpls_record_fifo_t *tcpls_record_queue_new(int max_record_num) {
  tcpls_record_fifo_t *fifo = malloc(sizeof(*fifo));
  memset(fifo, 0, sizeof(*fifo));
  if (fifo == NULL)
    return NULL;
  fifo->queue = malloc(max_record_num*2*sizeof(uint32_t));
  memset(fifo->queue, 0, max_record_num*2*sizeof(uint32_t));
  if (fifo->queue == NULL)
    goto Exit;
  fifo->size = 0;
  fifo->front_idx = 0;
  fifo->back_idx = 0;
  fifo->max_record_num = max_record_num;
  return fifo;
Exit:
  free(fifo);
  return NULL;
}

/**
 * Push a record to the front of the queue
 *
 * return MEMORY_FULL, OK
 */
queue_ret_t tcpls_record_queue_push(tcpls_record_fifo_t *fifo, uint32_t
    stream_seq, uint32_t reclen) { if (fifo->size == fifo->max_record_num)
    return MEMORY_FULL;
  memcpy(&fifo->queue[fifo->front_idx], &stream_seq, sizeof(uint32_t));
  memcpy(&fifo->queue[fifo->front_idx+4], &reclen, sizeof(uint32_t));
  fifo->size++;
  if (fifo->front_idx == (fifo->max_record_num-1)*(2*sizeof(uint32_t))) {
    fifo->front_idx = 0;
  }
  else {
    fifo->front_idx += 2*sizeof(uint32_t);
  }
  return OK;
}

queue_ret_t tcpls_record_queue_pop(tcpls_record_fifo_t *fifo, uint32_t *stream_seq, uint32_t *reclen) {
  if (fifo->size == 0)
    return EMPTY;
  *stream_seq = *(uint32_t *) &fifo->queue[fifo->back_idx];
  *reclen = *(uint32_t *) &fifo->queue[fifo->back_idx+4];
  return tcpls_record_queue_del(fifo, 1);
}

queue_ret_t tcpls_record_queue_del(tcpls_record_fifo_t *fifo, int n) {
  while (n > 0) {
    if (fifo->size == 0)
      return EMPTY;
    if (fifo->back_idx == (fifo->max_record_num - 1)*2*sizeof(uint32_t)) {
      fifo->back_idx = 0;
    }
    else {
      fifo->back_idx+= 2*sizeof(uint32_t);
    }
    fifo->size--;
    n--;
  }
  return OK;
}

uint32_t tcpls_record_queue_seq(tcpls_record_fifo_t *fifo) {
  assert(fifo);
  assert(fifo->queue);
  return *(uint32_t *) &fifo->queue[fifo->back_idx];
}

void tcpls_record_fifo_free(tcpls_record_fifo_t *fifo) {
  if (!fifo)
    return;
  if (!fifo->queue) {
    free(fifo);
    return;
  }
  free(fifo->queue);
  free(fifo);
}

/* =================================================LIST===========================*/
/**
 * Create a new list_t containting room capacity items of size itemsize
 *
 * return NULL if an error occured
 */

list_t *new_list(int itemsize, int capacity) {
  list_t *list = malloc(sizeof(*list));
  if (!list)
    return NULL;
  if (!capacity)
    capacity+=1;
  list->items = malloc(itemsize*capacity);
  if (!list->items) {
    free(list);
    return NULL;
  }
  list->capacity = capacity;
  list->size = 0;
  list->itemsize = itemsize;
  return list;
}

/**
 * Add item to the end of the list. If the list's size has reached the capacity,
 * double its size and then add the item
 * return 0 if the item has been added, -1 if an error occured
 */

int list_add(list_t *list, void *item) {
  if (list->size == list->capacity) {
    list->items = realloc(list->items, list->capacity*2*list->itemsize);
    if (!list->items)
      return -1;
    list->capacity = list->capacity*2;
  }
  memcpy(&list->items[list->size*list->itemsize], item, list->itemsize);
  list->size++;
  return 0;
}


void *list_get(list_t *list, int itemid) {
  if (itemid > list->size-1)
    return NULL;
  return &list->items[list->itemsize*itemid];
}

int list_contain(list_t *list, void *item) {
  if (list->size == 0)
    return 0;
  for (int i = 0; i < list->size; i++) {
    if (!memcmp(&list->items[i*list->itemsize], item, list->itemsize) == 0)
      return 1;
  }
  return 0;
}

/**
 * remove item  from the list if this item is inside, then move the items to keep
 * them continuous
 * Note: if several same item are in the list, remove the first one
 * return -1 if an error occured or if the item isn't part of the list
 */

int list_remove(list_t *list, void *item) {
  if (list->size == 0)
    return -1;
  for (int i = 0; i < list->size; i++) {
    if (memcmp(&list->items[i*list->itemsize], item, list->itemsize) == 0) {
      if (i == list->size-1) {
        list->size--;
        return 0;
      }
      else {
        uint8_t *items_tmp[(list->size-i-1)*list->itemsize];
        /** Note: could do a memmove instead */
        memcpy(items_tmp, &list->items[(i+1)*list->itemsize], (list->size-i-1)*list->itemsize);
        memcpy(&list->items[i*list->itemsize], items_tmp, (list->size-i-1)*list->itemsize);
        list->size--;
        return 0;
      }
    }
  }
  return -1;
}

/**
 * Virtually clean the list
 */
void list_clean(list_t *list) {
  if (!list)
    return;
  list->size = 0;
}

void list_free(list_t *list) {
  if (!list)
    return;
  if (!list->items) {
    free(list);
    return;
  }
  free(list->items);
  free(list);
}

/*********************Stream buffers ****************************/

static int stream_buffer_cmp(const void *elem1, const void *elem2) {
  struct st_tcpls_stream_buffer *stream_buf1 = (struct st_tcpls_stream_buffer*) elem1;
  struct st_tcpls_stream_buffer *stream_buf2 = (struct st_tcpls_stream_buffer*) elem1;
  int val = stream_buf1->streamid - stream_buf2->streamid;
  if (val < 0)
    return -1;
  else if (val == 0)
    return 0;
  else
    return 1;
}

/**
 * Create a new tcpls_buffer_t * with rooms for nbr_expected_streams buffers.
 *
 * /!\ returns NULL if a tcpls_buffer_t * has already been created /!\
 */

tcpls_buffer_t *tcpls_stream_buffers_new(tcpls_t *tcpls, int nbr_expect_streams) {
  if (tcpls->buffer)
    return NULL;
  tcpls_buffer_t *buf = malloc(sizeof(tcpls_buffer_t));
  if (!buf)
    return NULL;
  memset(buf, 0, sizeof(tcpls_buffer_t));
  buf->bufkind = STREAMBASED;
  buf->stream_buffers = new_list(sizeof(struct st_tcpls_stream_buffer), nbr_expect_streams);
  buf->wtr_streams = new_list(sizeof(streamid_t), nbr_expect_streams);
  if (!buf->stream_buffers || !buf->wtr_streams)
    return NULL;
  tcpls->buffer = buf;
  /** In case the application changes its aggregation-based buffer to a
   * stream-based buffering in the middle of the connection */
  if (tcpls->streams->size > 0) {
    tcpls_stream_t *stream;
    for (int i = 0; i < tcpls->streams->size; i++) {
      stream = list_get(tcpls->streams, i);
      if (stream->stream_usable)
        tcpls_stream_buffer_add(buf, stream->streamid);
    }
  }
  return buf;
}
/**
 * Creates a buffer expected to be used by the applcation when  the aggregation
 * mode is enabled
 * /!\ returns NULL if a tcpls_buffer_t * has already been created /!\
 */
tcpls_buffer_t *tcpls_aggr_buffer_new(tcpls_t *tcpls) {
  if (tcpls->buffer)
    return NULL;
  tcpls_buffer_t *buf = malloc(sizeof(tcpls_buffer_t));
  if (!buf)
    return NULL;
  memset(buf, 0, sizeof(tcpls_buffer_t));
  buf->bufkind = AGGREGATION;
  buf->decryptbuf = malloc(sizeof(ptls_buffer_t));
  if (!buf->decryptbuf) {
    free(buf);
    return NULL;
  }
  ptls_buffer_init(buf->decryptbuf, "", 0);
  tcpls->buffer = buf;
  return buf;
}


/**
 * When a stream is created, we need to add a buffer that the application can
 * use. Maintain the list of buffer ordered
 *
 */

int tcpls_stream_buffer_add(tcpls_buffer_t *buffers, streamid_t streamid) {
  if (buffers->bufkind != STREAMBASED)
    return -1;
  struct st_tcpls_stream_buffer stream_buffer;
  memset(&stream_buffer, 0, sizeof(stream_buffer));
  stream_buffer.decryptbuf = malloc(sizeof(ptls_buffer_t));
  stream_buffer.streamid = streamid;
  ptls_buffer_init(stream_buffer.decryptbuf, "", 0);
  if (!stream_buffer.decryptbuf)
    return -1;
  list_add(buffers->stream_buffers, &stream_buffer);
  if (streamid > buffers->max_streamid)
    buffers->max_streamid = streamid;
  else {
    qsort(buffers->stream_buffers->items, buffers->stream_buffers->size,
        sizeof(struct st_tcpls_stream_buffer), stream_buffer_cmp);
  }
  return 0;
}

int tcpls_stream_buffer_remove(tcpls_buffer_t *buffers, streamid_t streamid) {
  if (buffers->bufkind != STREAMBASED)
    return -1;
  struct st_tcpls_stream_buffer *stream_buffer;
  if (streamid > buffers->max_streamid)
    return -1;
  /** Ensure that buffers->max_streamid is still relevant after removal */
  else if (streamid == buffers->max_streamid && buffers->stream_buffers->size > 1) {
    stream_buffer = list_get(buffers->stream_buffers, buffers->stream_buffers->size-2);
    buffers->max_streamid = stream_buffer->streamid;
  }
  else if (streamid == buffers->max_streamid && buffers->stream_buffers->size == 1) {
    buffers->max_streamid = 0;
  }
  for (int i = 0; i < buffers->stream_buffers->size; i++) {
    stream_buffer = list_get(buffers->stream_buffers, i);
    if (stream_buffer->streamid == streamid)
      return list_remove(buffers->stream_buffers, stream_buffer);
  }
  return -1;
}

static struct st_tcpls_stream_buffer * pivot_search_stream_buffer(tcpls_buffer_t *buffers, int left, int right, streamid_t streamid) {
  int center = (right+left)/2;
  struct st_tcpls_stream_buffer *stream_buffer;
  stream_buffer = list_get(buffers->stream_buffers, center);
  if (stream_buffer->streamid == streamid)
    return stream_buffer;
  else if (left == right)
    return NULL;
  else if (stream_buffer->streamid < streamid)
    return pivot_search_stream_buffer(buffers, center+1, right, streamid);
  else
    return pivot_search_stream_buffer(buffers, left, center, streamid);
}

/**
 * Does a binary search of the streamid
 */

ptls_buffer_t *tcpls_get_stream_buffer(tcpls_buffer_t *buffers, streamid_t streamid) {
  if (streamid < 0 || streamid > buffers->max_streamid || buffers->stream_buffers->size == 0)
    return NULL;
  struct st_tcpls_stream_buffer *stream_buffer = pivot_search_stream_buffer(buffers, 0, buffers->stream_buffers->size-1, streamid);
  if (stream_buffer) {
    return stream_buffer->decryptbuf;
  }
  else {
    return NULL;
  }
}


/**
 * Free a tcpls_buffer_t *
 */
void tcpls_buffer_free(tcpls_t *tcpls, tcpls_buffer_t *buf) {
  if (!buf)
    return;
  if (buf->bufkind == AGGREGATION) {
    ptls_buffer_dispose(buf->decryptbuf);
  }
  else {
    for (int i = 0; i < buf->stream_buffers->size; i++) {
      struct st_tcpls_stream_buffer *stream_buffer = (struct st_tcpls_stream_buffer *) list_get(buf->stream_buffers, i);
      ptls_buffer_dispose(stream_buffer->decryptbuf);
    }
    list_free(buf->stream_buffers);
    list_free(buf->wtr_streams);
  }
  tcpls->buffer = NULL;
  free(buf);
}


