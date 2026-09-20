# Releases

## Unreleased

- Support for HelloRetryRequest (RFC 8446, section 4.1.4) on both sides.
  A client that receives one validates it and sends a second ClientHello with a key share for the group the server
  selected. The cookie extension is echoed, the early_data extension is removed, and the pre_shared_key extension is
  updated with a recomputed obfuscated ticket age and binder.
  A server sends one when the client's key share is for a group it does not offer, whilst the client did offer a group
  it can use; this is what RFC 8446, section 4.1.1 requires, where the server previously aborted the handshake. The
  server never sends a cookie, as it keeps its state between the two ClientHello messages.
- Added `TlsServerEngine.addSupportedGroups` to configure which named groups the server offers for key exchange. When
  it is not used, the server offers all groups its key exchange factory can provide, as before.
- **Breaking**: `ServerMessageSender` has a new method `send(HelloRetryRequest)`; implementations must add it.
- Added `CookieExtension` (RFC 8446, section 4.2.2); it was parsed as an `UnknownExtension` before. Note that a cookie
  in a ServerHello (as opposed to a HelloRetryRequest) is now rejected with an `illegal_parameter` alert.
- `BinderCalculator.computePskBinder` takes the preceding transcript as an extra parameter, which is needed for
  computing the binder of a second ClientHello. The single-argument method remains available as a default method.

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
