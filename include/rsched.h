#ifndef rsched_h
#define rsched_h
#include "picotypes.h"
#include "picotls.h"
#include "picotcpls.h"

int simple_read_scheduler(tcpls_t *tcpls, int transportid, tcpls_buffer_t *decryptbuf, void *data);

#endif
