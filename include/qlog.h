#ifndef qlog_h
#define qlog_h

#include "qlogtypes.h"
int qlog_init_log(int is_server);
int qlog_transport_log(const qlog_dir_evt evt_dir, uint32_t mpseq,
  size_t record_size, qlog_record_evt evt, uint8_t ttype, uint32_t seq, uint32_t streamid);
int qlog_close_log(int is_server);
int qlog_handshake_log(const qlog_dir_evt evt_dir, qlog_record_evt evt, qlog_handshake_evt hevt, uint32_t seq, size_t msg_size);
int qlog_encryptedextensions_log(const qlog_dir_evt evt_dir, qlog_record_evt evt, qlog_handshake_evt hevt, uint32_t seq, size_t msg_size);
int qlog_encryptedextensions_init(const qlog_dir_evt evt_dir);
int qlog_encryptedextensions_addextension(const qlog_dir_evt evt_dir, qlog_extensions_evt evt);

#endif
