# Releases

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
