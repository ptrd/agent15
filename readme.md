![Agent15](https://raw.githubusercontent.com/ptrd/agent15/refs/heads/master/docs/media/Logo_Agent15_rectangle.png)

# A (partial) TLS 1.3 implementation in Java

[![Maven Central](https://img.shields.io/maven-central/v/tech.kwik/agent15.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/tech.kwik/agent15)
[![Javadoc](https://img.shields.io/badge/Javadoc-online-blue.svg)](https://ptrd.github.io/agent15/javadoc)

Agent15 is an open source implementation of the [handshake protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-4) of TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/info/rfc8446/)), running on Java 11.
It was developed for, and is used by [Kwik](https://github.com/ptrd/kwik/), a 100% pure Java implementation of the QUIC protocol. 
QUIC uses TLS 1.3 for encryption, but only the handshake layer, not the record layer (see [RFC 9001, sec 3](https://www.rfc-editor.org/rfc/rfc9001.html#name-protocol-overview)).

Agent15 is created and maintained by Peter Doornbosch. The latest greatest can always be found on [GitHub](https://github.com/ptrd/agent15).

## Status

Agent15 implements all of the handshake protocol that is needed to setup and maintain a QUIC connection, including
[HelloRetryRequest](https://www.rfc-editor.org/info/rfc8446/#section-2.1),
[session resumption](https://datatracker.ietf.org/doc/html/rfc8446#section-2.2) 
and
[0-RTT](https://datatracker.ietf.org/doc/html/rfc8446#section-2.3).

Not all TLS 1.3 handshake messages are implemented because there are some that are not used in the QUIC protocol:

- EndOfEarlyData: see https://www.rfc-editor.org/rfc/rfc9001.html#name-removing-the-endofearlydata
- KeyUpdateRequest: see https://www.rfc-editor.org/rfc/rfc9001.html#name-key-update

Not all extensions listed in [RFC 8446](https://www.rfc-editor.org/info/rfc8446/) are supported, see the [source](https://github.com/ptrd/agent15/tree/master/core/src/main/java/tech/kwik/agent15/extension/) for an overview of which extensions are supported. 
However, the message parser will create an `UnknownExtension` object for unsupported extensions, so parsing will not fail 
(as it would for the unsupported handshake message types).

Agent15 also implements [RFC 10024](https://www.rfc-editor.org/info/rfc10024/): "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3" and "ML-DSA" as specified by [Use of ML-DSA in TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/).
All Post-Quantum cryptography is provided by means of a separate module, `agent15-pqc`, which requires Java 25.

#### QUIC extension support

QUIC defines a custom TLS extension for carrying [Transport parameters](https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e),
this is supported by Agent15 by means of a custom extension parser function that can be injected by the client application.


### Supported signature algorithms

Agent15 core supports the following digital signatures:

- rsa_pkcs1_sha256 (for certificates only, in accordance with TLS 1.3 specification)
- rsa_pss_rsae_sha256
- rsa_pss_rsae_sha384
- rsa_pss_rsae_sha512
- ecdsa_secp256r1_sha256
- ecdsa_secp384r1_sha384
- ecdsa_secp521r1_sha512

and the post-quantum module supports

- mldsa44
- mldsa65
- mldsa87

### Supported key exchange algorithms

For key exchange, the following elliptic curves ("named groups") are supported:

- secp256r1, secp384r1 and secp521r1
- X25519, X448

and the post-quantum hybrid key exchanges:

- X25519MLKEM768
- SecP256r1MLKEM768 and SecP384r1MLKEM1024


### Supported cipher suites

As Agent15 does not implement the TLS record layer, it does not (need) to implement cipher suites either; however,
it does limit settings ciphers to the ones defined in [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4).

### Features

The engines support session resumption with a PSK (obtained via a NewSessionTicket message). The server uses an in-memory
cache to store session tickets, so a restart invalidates all tickets.
Client authentication (by means of a client certificate) is supported in the client engine, but not yet for the server engine.

### Usage

Maven coordinates:

    <dependency>
        <groupId>tech.kwik</groupId>
        <artifactId>agent15</artifactId>
        <version>4.0</version>
    </dependency>


Client: instantiate a `TlsClientEngine` with a `ClientMessageSender` and a `TlsStatusEventHandler` and call `startHandshake()` on it.
The `startHandshake` method that takes a list of key share groups makes the client offer a key share for each of them,
which avoids the extra round trip of a HelloRetryRequest when the server does not support the client's first choice.
The `ClientMessageSender` is the callback to let the client actually send the handshake messages. 
The `TlsStatusEventHandler` enables to client to react TLS events that are needed for the QUIC handshake,
e.g. when the early secrets or the handshake secrets are known (QUIC computes its own secrets based on the TLS secrets).
Any TLS message received should be passed to the engine's `received` method, which is done automatically by the `TlsMessageParser` 
when calling its `parseAndProcessHandshakeMessage()` method.

Server: instantiate a `TlsServerEngine`. In addition to a `ServerMessageSender` and a `TlsStatusEventHandler` that serve
analogous purpose as in the client case, the server certificate and its private key need to be provided as well. 
As with the client, any TLS message received should be passed to the engine, which will take care of sending all necessary 
messages back to the client.

Which named groups the server offers for key exchange can be configured with `TlsServerEngine.setSupportedGroups`;
by default it offers all groups its key exchange factory can provide, which is what makes the hybrid post-quantum
groups available as soon as the `agent15-pqc` module is on the class path.

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

Many thanks to Michael Driscoll ([@xargsnotbombs](https://twitter.com/xargsnotbombs)) for writing 
the brilliant ["The New Illustrated TLS Connection, Every byte explained and reproduced"](https://tls13.ulfheim.net/);
I never would have succeeded in writing a functional TLS library without this help. 
Thanks to Piet van Dongen for creating the marvellous logo!
Thanks to Chris Burdess for his help to implement RFC 10024 (Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms).

## License

This program is open source and licensed under LGPL (see the LICENSE.txt and LICENSE-LESSER.txt files in the distribution). 
This means that you can use this program for anything you like, and that you can embed it as a library in other applications, even commercial ones. 
If you do so, the author would appreciate if you include a reference to the original.
 
As of the LGPL license, all modifications and additions to the source code must be published as (L)GPL as well.

If you want to use the source with a different open source license, contact the author.