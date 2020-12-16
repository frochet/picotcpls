picotcpls
===

Picotcpls is a fork of [picotls](https://github.com/h2o/picotls), a  [TLS 1.3 (RFC 8446)](https://tools.ietf.org/html/rfc8446) protocol stack written in C, with the following features:

* From picotls:
  * support for two crypto engines
    * "OpenSSL" backend using libcrypto for crypto and X.509 operations
    * "minicrypto" backend using [cifra](https://github.com/ctz/cifra) for most crypto and [micro-ecc](https://github.com/kmackay/micro-ecc) for secp256r1
  * support for PSK, PSK-DHE resumption using 0-RTT
  * API for dealing directly with TLS handshake messages (essential for QUIC)
  * support for new extensions: Encrypted SNI (wg-draft-02), Certificate Compression (wg-draft-10)
* From TCPLS:
  * API to deal with a novel TCP extensibility mechanism
    * Allows setting and configuring the peer's TCP stack for our
      connections
    * Can inject BPF bytecode to the peer to set a new congestion
      control mechanism
    * Essentially any TCP socket option (a few are supported so far)
  * A wrapper to handle network connections
  * QUIC-like streams
  * 0-RTT TCPLS handshakes
  * Application-level Connection Migration (simplistic API code flow to
    trigger a migration)
  * Multipath
  * (ongoing: A Failover mechanism; a kind of automatic connection
    migration in case of network failure)
  * (ongoing: Authenticated connection closing)


picotcpls is a research-level implementation of TCPLS, a novel
cross-layer extensibility mechanism for TCP designed to offer a
fine-grained control of the transport protocol to the application layer.
The mere existence of this research comes from several observations:

* Since Let's Encrypt's success, TLS is now massively deployed, and we should not expect unsecure TCP
  connections to occur over untrusted networks anymore.
* TCP suffers from severe extensibility issues caused by middlebox
  interferences, lack of space in its header and the difficulty to
  propagate new implementation features
* There is a performance gap between what some application usage get
  (e.g., web), and what they could expect to get with proper
  configuration of the transport layer to match their usage of the
  network.

The goal of TCPLS is threefold:

* Providing a simple API to the application for potentially complex
  transport layer operations (e.g., connection migration or multipathing)
* Showing that alternative extensibility mechanisms can be powerful
* Showing the quest for maximum Web performance with QUIC can be matched by
  TCPLS, or even improved under several metrics.

/!\ There are probably bugs left, and the API may evolve over time. Use
it for fun and experiments /!\

/!\ The current implementation is cryptographically unsecure (IV derivation bug remains to be fixed; not a priortiy tho) /!\

Like picotls, the implementation of picotcpls is licensed under the MIT license.


Building picotcpls
---

If you have cloned picotpls from git then ensure that you have initialised the submodules:
```
% git submodule init
% git submodule update
% sudo apt-get install faketime libscope-guard-perl libtest-tcp-perl
```

Build using cmake:
```
% cmake .
% make
% make check
```

Usage documentation
---

### Overview

This is an overview of an ongoing research and development project. Many
things are missing and some features may change in the future. The
current description is intented to provide an intuition of the potential usefulness
TCPLS.

### Initializing the Context

picotcpls currently use picotls's context. First, follow the
[guideline](https://github.com/h2o/picotls/wiki/Using-picotls#initializing-the-context)
provided by picotls's wiki to manipulate a `ptls_context_t ctx` to setup
SSL. This context is meant to be a static attribute common to many TCPLS
connections; hence its configuration is supposed to be common to all of
them.

Regarding TCPLS, client and server must advertise support for TCPLS. In
our implementation, this exchange of information is going to be
triggered by setting  

`ctx.support_tcpls_options = 1`  

The TLS handshake is designed to only expose the information that we're
doing TCPLS, but not how exactly we configure the new TLS/TCP stack, for
which the information is private to a passive observer (assuming no
side-channels).  

### Managing the Connection Object

Similarly to picotls, we offer a creation and a destruction function.
The `tcpls_new` function takes as argument a `ptls_context_t*` and a
boolean value indicating whether the connection is server side or not.  

`tcpls_t *tcpls = tcpls_new(&ctx, is_server);`  

The application is responsible for freeing its memory, using
`tcpls_free(tcpls)` when the connection wants to be closed.  

A tcpls connection may have multiple addresses and streams attached
them. Addresses require to be added first if we expect to use them for
a TCPLS connection.

### Adding addresses

picotls supports both v4 and v6 IP addresses, which the application can
advertize by calling   

`tcpls_add_v4(ptls_t *tls, struct sockaddr_in
*addr, int is_primary, int settopeer, int is_ours)`  

or  

`tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary,
int settopeer, int is_ours)`.  

`is_primary` sets this address as the default. `settopeer` tells TCPLS
to announce this address to the peer. If this connection is a
server-side connection, and if this function is called before the
hanshake, then TCPLS will send this address as part of a new
EncryptedExtension. The client application is advertised of the new
address through an connection event mechanism that we will discuss below.  

If this function called before the handshake and the connection is
client-side, then the information will be sent as part of the first data
sent during this connection. This restriction is designed to avoid
making more entropy for fingerprinting, avoiding the client-side handshake to look
different depending on the number of encrypted addresses advertized.  

If these functions are called after the handshake, then the application
can either call `tcpls_send_transport_opt` to send addresses right away or
wait the next exchange of application-level data, in which new addresses
will be also included.

### Connecting with multiple addresses

picotcpls provides `tcpls_connect(ptls_t *tls, struct sockaddr *src,
struct sockaddr *dest, struct timeval *timeout)` to make TCP connections
to the server. The bi-partite graph connection can be made explicit by
calling several times `tcpls_connect`. For
example, assuming that both the client and the server have a v4 and v6:  

```
tcpls_connect(tls, src_v4, dest_v4, NULL);
tcpls_connect(tls, src_v6, dest_v6, timeout);
```
spawns two TCP connections between the two pairs of addresses, for which
the second `tcpls_connect` waits until all connected or the timeout
fired. TCPLS monitors at which speed those connection connected and
automatically set as primary the one that connected the faster.
Callbacks events are triggered when a connection succeeded, and the
application may know which addresses are usable to attach streams, and
which ones require to call tcpls_connect again in case the timeout fired.

Note that this design allows the application to implement various
connectivity policies, such as happy eyeball with a `timeout1` of 50ms:

```
if (tcpls_connect(tls, src_v4, dest_v4, timeout1) > 0)
   tcpls_connect(tls, src_v6, dest_v6, timeout2);
```
This code instructs TCPLS to connect to the IPv4 and use it if the
connection is successful under 50ms. If it is not, it tries the v6 and
then set as primary the fastest of the two (assuming both connected in
the second call).  

Setting src and dest to `NULL` would make tcpls_connect tries a full
mesh TCP connections between all addresses added with `tcpls_add_v4` and `tcpls_add_v6`.  
Setting only src to `NULL` makes tcpls_connect uses the default system's
routing rules to select a src address.

New connections can be made at any time of the initial connection
lifetime and may offer to the application an easy interface to program
failover mechanism (or let TCPLS automatically handle failover) or
aggregation of bandwidth with multipathing.

### Handshake

picotcpls simply offer a wrapper around picotls's interactive hanshake (`ptls_handshake`):  

`tcpls_handshake(ptls_t *tls, ptls_handshake_properties_t *properties);`

this function waits until the handshake is complete or an error occured.
It may also triggers various callbacks depending on events occuring in
the handshake.

`properties` defines handshake configurations that the client and server
can configure to modify the TCPLS handshake, such as the connection in
which the handshake takes place (in case of multiple connections).

In case of multiple connections (using multiple addresses), a first
complete handshake must have occured over a chosen connection configured
with the properties. Note, if `properties == NULL` then the handshake is
performed over the primary connection. Then, to be able to use the other
connected addresses, you must perform a JOIN TCPLS handshake by
configuring the appropriate connection id within the properties and set
`proprties->client.mpjoin = 1`, and then call `tcpls_handshake()` for
each of the desired connection id.

Server-side, if multiple addresses are announced to the client during
the hanshake, the server must perform any next tcpls_handshake() with a
configured mpjoin callback `int (*received_mpjoin_to_process)(int
socket, uint8_t *connid, uint8_t *cookie)`  

`properties->received_mpjoin_to_process = &my_function;`

TCPLS will pass the connid of the TCPLS session corresponding to the
received JOIN, alongside the received one-time cookie and the socket
in which this MPJOIN handshake was received. In this case
tcpls_handshake() will return PTLS_ERROR_HANDSHAKE_IS_MPJOIN to indicate
the server that this handshake wasn't from a new client. The server can
then call `tcpls_accept(tcpls_t *tcpls, int socket, uint8_t
*cookie, unint32_t transportid)` assuming it stored a mapping between connid and tcpls_t*. This
function would properly link the TCP connection to the given tcpls
session if the cookie is valid.

#### Handshake properties

A set of handshake properties can be configured, which influences the
behaviour of `tcpls_handshake()` such as connecting in 0-RTT TCP+TLS,
connecting in 0-RTT in TLS only, joining an existing connection, etc.

#### TCPLS 0-RTT

`properties->client.zero_rtt` must be set to 1 prior to calling
`tcpls_handshake`. Besides, no connection should have been already established
over the link in which the tcpls handshake is about to take place.


### Adding / closing streams

The API allows the application to attach streams to connections (note,
src and dest would further be replaced by a transport connection
wrapper). If no streams are created, TCPLS will send a control message
alongside the first bytes of application data sent with `tcpls_send`

`streamid_t tcpls_stream_new(tcpls_t *tcpls, struct sockaddr *src, struct sockaddr *dest)`

Streams need to be attached before we can use them:

`int tcpls_streams_attach(tcpls_t *tcpls, streamid_t streamid, int
sendnow)`

streamid being the streamid in which the control message will be sent;
leave to 0 for default.

Then, TCPLS would close the underlying transport connection when no
streams are attached anymore. When calling

`tcpls_stream_close(tcpls_t *tls, streamid_t streamid, int sendnow)`,

To close the stream, 2 control messages are exchanged: a STREAM_CLOSE is
sent to the peer, which answers with a STREAM_CLOSE_ACK. When received
the STREAM_CLOSE_ACK, TCPLS eventually also close the TCP connection if
no other streams are attached. Callbacks for a STREAM_CLOSE are
triggered when the stream is dettached (when it is ACKED, or when the
STREAM_CLOSE is received).

Note: might be better to trigger the callback when the STREAM_CLOSE is sent,
and not when the STREAM_CLOSE_ACK is received. We cannot write any more
message on it anyway.

#### Multipath

Multipath can be seamlessly enabled by opening streams on different destinations
of the same TCPLS connection. Sending over the different streams would
make the TCPLS aggregates the bandwith of the different TCP connection,
assuming the internal reordering buffer does not reach its size limit
(currently unspecified).

The current implementation logic is to make the sender multipath aware,
and the receiver passive. That is, the only control the receiver has on
the multipath notion is from the scheduler used when calling
`tcpls_receive`. This scheduler can be set by the receiver TODO


### Sending / receiving data

TCPLS gives a simple `tcpls_send` and `tcpls_receive` interface to
exchange data.

#### Sending data

`size_t tcpls_send(tcpls_t *tcpls, streamid_t streamid, const void *input,
size_t nbytes)`

returns the number of bytes sent (counting the TLS overhead).

#### Receiving data

`int tcpls_receive(ptls_t *tls, ptls_buffer_t *decryptbuf, size_t
nbytes, struct timeval *tv)`

returns either TCPLS_HOLD_DATA_TO_READ,
TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ, TCPLS_OK or -1

TCPLS_HOLD_DATA_TO_READ means that there is more than nbytes directly
available. TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ means that TCPLS hold
some out of order data that we expect eventually be available to read.
TCPLS_OK means that we have nothing more left.  

All read data (at most nbytes at each call) is put within decryptbuf.
The current number of bytes within the buffer can be reach with
`decryptbuf->off`, and the pointer to the first byte is at
`decryptbuf->base`.

`tv` is a timeout which tells tcpls_receive how much time it must wait
at most for a read() sys call. Setting NULL tells tcpls not to wait.

### Handling events

Several callbacks might be configured for events such as:

* STREAM_OPEN, STREAM_CLOSE
* CONN_OPEN, CONN_CLOSE
* JOIN

TODO

Code examples
---

TODO

Using the cli command
---

Run the test server (at 127.0.0.1:8443):
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```

Connect to the mtest server:
```
% ./cli 127.0.0.1 8443
```

Using resumption:
```
% ./cli -s session-file 127.0.0.1 8443
```
The session-file is read-write.
The cli server implements a single-entry session cache.
The cli server sends NewSessionTicket when it first sends application data after receiving ClientFinished.

Using early-data:
```
% ./cli -s session-file -e 127.0.0.1 8443
```
When `-e` option is used, client first waits for user input, and then sends CLIENT_HELLO along with the early-data.

License
---

The software is provided under the MIT license.
Note that additional licences apply if you use the minicrypto binding (see above).
