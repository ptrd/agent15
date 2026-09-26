# Releases

## 4.0 (2026-09-27)

Provides support for post-quantum (hybrid) key exchange and HelloRetryRequest. 
Support for post-quantum is provided by the new `agent15-pqc` module that requires Java 25. 
The core module runs on Java 11 as before.

Contains quite some breaking changes, but unless you depend directly on the handshake message or extension classes, 
the only relevant ones are:
-  new method `send(HelloRetryRequest)` in `ServerMessageSender`; implementations must add it,
- `Extension` is now an interface instead of an abstract class.

### Post-quantum key exchange

- Added the three hybrid key agreement mechanisms of RFC 10024: `X25519MLKEM768`, `SecP256r1MLKEM768` and
  `SecP384r1MLKEM1024` (new `TlsConstants.NamedGroup` values).
- These are based on ML-KEM, for which `java.security.KEM` (Java 25) is used, whilst agent15 targets Java 11.
  The project is therefore split into two modules: `tech.kwik:agent15` (the TLS handshake implementation, Java 11) and
  `tech.kwik:agent15-pqc` (the hybrid key exchange, Java 25). The hybrid groups are available exactly when
  `agent15-pqc.jar` is present; core loads it as a `KeyExchangeFactory` service (`ServiceLoader`), so no code change
  is needed to use them, just the extra dependency.
- Added support for the classical groups secp384r1, secp521r1 and x448 (the hybrid groups build on them);
  before, only secp256r1 and x25519 actually worked.
- A client can offer a key share for more than one named group, with the new
  `TlsClientEngine.startHandshake(List<NamedGroup> keyShareGroups, List<NamedGroup> supportedGroups, List<SignatureScheme>)`.
  This avoids the extra round trip of a HelloRetryRequest when the server does not support the client's first choice,
  which is especially useful when offering a hybrid group next to a classical one.
- Added `TlsServerEngine.setSupportedGroups` to configure which groups the server offers for key exchange; when it is
  not used, the server offers all groups its key exchange factories provide (thus including the hybrid groups when
  `agent15-pqc` is present).
- All key exchange logic has moved out of the engines, `TlsState` and `KeyShareExtension` into `KeyExchange`
  implementations, which are created by a `KeyExchangeFactory` (both new interfaces in `tech.kwik.agent15.engine`).
- **Breaking**: `KeyShareExtension` and its nested `KeyShareEntry` now work with the raw key exchange data
  (`byte[]`) instead of a `java.security.PublicKey`, because a hybrid key share is not a public key. The constructors
  taking an (`EC`)`PublicKey` are replaced by one taking a `byte[]`, `KeyShareEntry.getKey()` by
  `getKeyExchangeData()`, and the `ECKeyShareEntry` subclass and the `reverse(byte[])` helper are gone.

### HelloRetryRequest

- Added support for HelloRetryRequest (RFC 8446, section 4.1.4) on both sides.
  The server never sends a cookie, as it keeps its state between the two ClientHello messages.
- Added the `HelloRetryRequest` handshake message and the `CookieExtension` (RFC 8446, section 4.2.2), which was parsed
  as an `UnknownExtension` before. Note that a cookie in a ServerHello (as opposed to a HelloRetryRequest) is now
  rejected with an `illegal_parameter` alert.
- The server now checks the rules that RFC 8446, section 4.2.8 imposes on the client's key shares, which it MAY do: a
  ClientHello with two key shares for the same group, with a key share for a group that is not in its supported groups,
  or with key shares in another order than its supported groups, is rejected with an `illegal_parameter` alert.
- **Breaking**: `ServerMessageSender` has a new method `send(HelloRetryRequest)`; implementations must add it.
- **Breaking**: `ServerHello.parse` returns a `HandshakeMessage`, because a message of type server_hello can also be a
  hello retry request. `MessageProcessor.received(HelloRetryRequest, ProtectionKeysType)` is a default method (that
  raises an `unexpected_message` alert), so implementations of that interface do not have to change.

### Breaking changes in the public interfaces

- `TlsClientEngine` has a new method `received(HelloRetryRequest, ProtectionKeysType)` and `TlsServerEngine` a new
  method `setSupportedGroups(List<NamedGroup>)`; only classes that implement these interfaces themselves are affected.
- `BinderCalculator.computePskBinder` takes the preceding transcript as an extra parameter, which is needed for
  computing the binder of a second ClientHello; the single argument method remains available as a default method, but
  implementations must now implement `computePskBinder(byte[] transcriptPrefix, byte[] partialClientHello)`.
- `Extension` is an interface instead of an abstract class; custom extensions must use `implements` instead of
  `extends`. Its `protected` helper method `parseExtensionHeader` moved to `ExtensionBlockParser` (as a public static
  method), which is the new home for extension (block) parsing.
- `ExtensionParser.apply` is deprecated in favour of the new `parse` method (which by default delegates to `apply`);
  `apply` will be removed in a future release.

### Other breaking changes in handshake messages and extensions

- All parsing constructors and instance `parse` methods of handshake messages and extensions are replaced by static
  `parse` methods, e.g. `new ClientHello(buffer, parser)` becomes `ClientHello.parse(buffer, parser)` and
  `new ServerHello().parse(buffer, length)` becomes `ServerHello.parse(buffer, length)`.
- `ClientHello`: the constructors that take a single named group and key share are replaced by the one taking a
  `List<KeyShareExtension.KeyShareEntry>`, and the supported groups are no longer derived from the key share group, so
  they must always be given; the convenience constructors taking an `ECPublicKey` are gone.
- `ClientHelloPreSharedKeyExtension.calculateBinder` takes the preceding transcript as an extra parameter.
- `HandshakeMessage.checkForDuplicateExtensions` moved to `ExtensionBlockParser`.

## 3.3 (2026-06-19)

Security hardening and protocol correctness fixes.

- Client only keeps two new session tickets.
- Improve EC curve detection; TlsServerEngineFactory constructor with curve parameter is now deprecated because 
  it should not (never) be necessary anymore to manually pass the curve name.
- Fixed that DefaultHostnameVerifier should compare hostnames ignoring case. 
- Fixed that DefaultHostnameVerifier should not fallback to CN when SAN extension is present.

## 3.2 (2026-04-18)

Security hardening and protocol correctness fixes.

- Added `getType()` method added to `Extension` class.
  This is strictly speaking a breaking change, but the fix is trivial.
- Reject ClientHello messages that contain duplicate extensions.
- Put a cap on parsed handshake message size.
- Put a size limit on the session registry.
- Verify that the server has selected an identity within the range offered by the client.
- Remove debug logging of secrets.
- Fix: TLS versions other than 1.3 should not be accepted.
- Fix: wildcard certificates should not match the root domain, only sub-domains.

## 3.1 (2025-04-24)

- Added method to AlgorithmMapping interface to map signature algorithm properly.
- Added method to parse handshake message without immediately processing it.

## 3.0 (2025-01-05)

Moved all classes to new package structure, starting with `tech.kwik.agent15`.
To migrate projects using agent15, simply do a find-and-replace `net.luminis.tls` by `tech.kwik.agent15`.

## 2.3 (2024-10-19)

- added dispose method to TlsServerEngineFactory
- TlsServerEngineFactory constructors now only throw CertificateException, no IOException or InvalidKeySpecException anymore.
  This is strictly speaking a breaking change, but the fix is trivial.

## 2.2 (2024-08-14)

Server engine fixes / improvements:
- Added option to explicitly specify the certificate's public key EC curve, in case this can not be determined automatically.  
- Implement proper negotiation between client and server concerning signature algorithm.
- Fixed server engine to base the signature algorithm used for the certificate verification on the type of the certificate's public key.

## 2.1 (2024-08-04)

Added client engine support for signature algorithms ecdsa_secp384r1_sha384 and ecdsa_secp521r1_sha512.

## 2.0 (2024-06-15)

Made agent15 a Java module, with module name `tech.kwik.agent15`. 
In order for the module to have proper exports, lots of classes and interfaces changed package; 
some classes were split in interface and implementation and a factory class was introduced for 
TlsClientEngine, so clients don't have to have direct access to its implementation.

- added class TlsClientEngineFactory
- moved TlsEngine implementation to class TlsEngineImpl and moved it to package `net.luminis.tls.engine.impl`
- converted TlsEngine into an interface
- moved TlsClientEngine implementation to class TlsClientEngineImpl and moved it to package `net.luminis.tls.engine.impl`
- converted TlsClientEngine into an interface
- moved TlsServerEngine implementation to class TlsServerEngineImpl and moved it to package `net.luminis.tls.engine.impl`
- converted TlsClientEngine into an interface
- moved the following classes to package `net.luminis.tls.engine`
  - MessageProcessor
  - ClientMessageProcessor
  - ServerMessageProcessor
  - ClientMessageSender
  - ServerMessageSender
  - HostnameVerifier
  - DefaultHostnameVerifier
  - CertificateWithPrivateKey
  - TlsStatusEventHandler
  - TlsMessageParser
  - TrafficSecrets
  - TlsSession
  - TlsSessionRegistry
  - TlsServerEngineFactory
- moved the following classes to package `net.luminis.tls.engine.impl`
  - TlsState
  - TranscriptHash
  - TlsSessionRegistryImpl
- removed (unused) class Message

## 1.1 (2024-03-30)

- Use Java KeyStore object to pass certificate and private key to TlsServerEngine.
- Accept ECDSA certificates as server certificate.

## 1.0.6 (2024-01-13)

Ignore unknown code points while parsing messages and extensions.

## 1.0.5 (2023-12-22)

Ignore unknown algorithms when parsing signature algorithms extension.

## 1.0.4 (2023-11-05)

Relocated maven artifact to `tech.kwik` group id.

## 1.0.3 (2023-11-05)

No changes, corrected pom.

## 1.0.2 (2023-11-04)

No changes, corrected pom.

## 1.0.1 (2023-10-20)

Updated test dependencies and HKDF library.

## 1.0 (2023-10-08)

First official release published to maven.
