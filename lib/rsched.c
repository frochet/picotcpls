/**
 * \file rsched.c
 *
 * \brief Hold implementations for multi connection schedulers which the
 * receiver can set to process bytes from the different connections
 */

#include "rsched.h"

/**
 * Simply call recv once.
 *
 * data is whatever data structure the application may want to remember and use
 * 
 * returns TCPLS_OK, TCPLS_HOLD_DATA_TO_READ or
 * TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ.
 * or -1 upon error
 */

int simple_read_scheduler(tcpls_t *tcpls, int transportid, tcpls_buffer_t
    *buf, void *data) {
  connect_info_t *con;
  int rret = 0, ret = 0;
  con =  connection_get(tcpls, transportid);
  if (con && con->state >= CONNECTED) {
    ret = recv(con->socket, tcpls->recvbuf, tcpls->recvbuflen, 0);
    rret = tcpls_internal_data_process(tcpls, con, ret, buf);
  }
  else
    return -1;
  return rret;
}
