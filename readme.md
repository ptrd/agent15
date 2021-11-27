![Agent15](https://bitbucket.org/pjtr/agent15/raw/master/docs/media/Logo_Agent15_rectangle.png)

# A (partial) TLS 1.3 implementation in Java

Agent15 is an open source implementation of the [handshake protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-4) of TLS 1.3. 
It was developed for, and is used by [Kwik](https://bitbucket.org/pjtr/kwik/src/master/), a 100% pure Java implementation of the QUIC protocol. 
QUIC uses TLS 1.3 for encryption, but only the handshake layer, not the record layer (see [RFC 9001, sec 3](https://www.rfc-editor.org/rfc/rfc9001.html#name-protocol-overview)).

Agent15 is created and maintained by Peter Doornbosch. The latest greatest can always be found on [BitBucket](https://bitbucket.org/pjtr/agent15).

## Status

Agent15 implements all of the handshake protocol that is needed to setup and maintain a QUIC connection.
[Session resumption](https://datatracker.ietf.org/doc/html/rfc8446#section-2.2) is supported for both roles (client and server),
[0-RTT](https://datatracker.ietf.org/doc/html/rfc8446#section-2.3)
is only supported for client connections.

Not all TLS 1.3 handshake messages are implemented (yet); some because they are not used at all in QUIC and others 
because the Kwik project does not use them. The messages that are not implemented are:

- HelloRetryRequest
- EndOfEarlyData: not used by QUIC, see https://www.rfc-editor.org/rfc/rfc9001.html#name-removing-the-endofearlydata
- KeyUpdateRequest: not used by QUIC, see https://www.rfc-editor.org/rfc/rfc9001.html#name-key-update

Also, not all extensions are supported, see the [source](https://bitbucket.org/pjtr/agent15/src/master/src/net/luminis/tls/extension/) 
for an overview of which extensions are supported. 
However, the message parser will create an `UnknownExtension` object for unsupported extensions, so parsing will not fail 
(as it does for unsupported handshake message types).

#### QUIC extension support

QUIC defines a custom TLS extension for carrying [Transport parameters](https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e),
this is supported by Agent15 by means of a custom extension parser function that can be injected by the client application.


### Supported cipher suites etc.

Agent15 supports the following cipher suites:

- TLS_AES_128_GCM_SHA256 (mandated by TLS 1.3 specification)
- TLS_CHACHA20_POLY1305_SHA256

So, TLS_AES_256_GCM_SHA384 is not (yet) supported, even though it SHOULD according to the TLS 1.3. specification.

The following digital signatures are supported:

- rsa_pkcs1_sha256 (for certificates only, in accordance with TLS 1.3 specification)
- rsa_pss_rsae_sha256
- rsa_pss_rsae_sha384
- rsa_pss_rsae_sha512
- ecdsa_secp256r1_sha256

The following elliptic curves are supported:

- secp256r1
- X25519

### Features

The engines support session resumption with a PSK (obtained via a NewSessionTicket message). The server uses an in-memory
cache to store session tickets, so a restart invalidates all tickets.
Client authentication (by means of a client certificate) is supported in the client engine, but not yet for the server engine.

### Usage

Client: instantiate a `TlsClientEngine` with a `ClientMessageSender` and a `TlsStatusEventHandler` and call `startHandshake()` on it.
The `ClientMessageSender` is the callback to let the client actually send the handshake messages. 
The `TlsStatusEventHandler` enables to client to react TLS events that are needed for the QUIC handshake,
e.g. when the early secrets or the handshake secrets are known (QUIC computes its own secrets based on the TLS secrets).
Any TLS message received should be passed to the engine's `received` method, which is done automatically by the `TlsMessageParser` 
when calling its `parseAndProcessHandshakeMessage()` method.

Server: instantiate a `TlsServerEngine`. In addition to a `ServerMessageSender` and a `TlsStatusEventHandler` that serve
analogous purpose as in the client case, the server certificate and its private key need to be provided as well. 
As with the client, any TLS message received should be passed to the engine, which will take care of sending all necessary 
messages back to the client.

#### Building

Use the gradle wrapper to build the library: `./gradlew build` (or on Windows: `gradlew.bat build`).

### Security

Certificates are checked using the default Java truststore. Other CA's can be used by setting a custom trustmanager.

All security aspects required by TLS are (supposed to be) implemented, I you find any discrepancies with the TLS 1.3 
specification, please file a bug report or contact the author.  
No security checks or reviews have been made for this library; use at your own risk. 

## Contact

If you have questions about this project, please mail the author (peter dot doornbosch) at luminis dot eu.

## Acknowledgements

Many thanks to Michael Driscoll ([@xargsnotbombs](https://twitter.com/xargsnotbombs)) for writing the brilliant ["The New Illustrated TLS Connection, Every byte explained and reproduced"](https://tls13.ulfheim.net/);
I never would have succeeded in writing a functional TLS library without this help. 
Thanks to Piet van Dongen for creating the marvellous logo!

## License

This program is open source and licensed under LGPL (see the LICENSE.txt and LICENSE-LESSER.txt files in the distribution). 
This means that you can use this program for anything you like, and that you can embed it as a library in other applications, even commercial ones. 
If you do so, the author would appreciate if you include a reference to the original.
 
As of the LGPL license, all modifications and additions to the source code must be published as (L)GPL as well.

If you want to use the source with a different open source license, contact the author.