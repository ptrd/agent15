/**
 * Agent15 is a Java implementation of the handshake protocol of TLS 1.3
 * (<a href="https://datatracker.ietf.org/doc/html/rfc8446#section-4">RFC 8446, section 4</a>).
 * It was developed for, and is used by, QUIC implementations: QUIC uses TLS 1.3 for encryption, but only the
 * handshake layer, not the record layer (see <a href="https://www.rfc-editor.org/rfc/rfc9001.html#name-protocol-overview">RFC 9001, section 3</a>).
 *
 * <h2>What is implemented</h2>
 * Agent15 implements all of the handshake protocol needed to set up and maintain a QUIC connection, including
 * <a href="https://datatracker.ietf.org/doc/html/rfc8446#section-2.2">session resumption</a> and
 * <a href="https://datatracker.ietf.org/doc/html/rfc8446#section-2.3">0-RTT</a>.
 * Because it targets QUIC, it implements only the handshake layer, not the TLS record layer. A few handshake messages
 * are intentionally not implemented, as they are not used with QUIC: {@code EndOfEarlyData} and {@code KeyUpdate}.
 * Unsupported extensions do not cause parsing to fail; the parser represents them with an {@code UnknownExtension}
 * object.
 *
 * <h2>Supported cryptography</h2>
 * Cipher suites: {@code TLS_AES_128_GCM_SHA256}, {@code TLS_AES_256_GCM_SHA384}, {@code TLS_CHACHA20_POLY1305_SHA256}.
 * <br>
 * Signature algorithms: {@code rsa_pkcs1_sha256} (certificates only), {@code rsa_pss_rsae_sha256},
 * {@code rsa_pss_rsae_sha384}, {@code rsa_pss_rsae_sha512}, {@code ecdsa_secp256r1_sha256}.
 * <br>
 * Named groups (key exchange): {@code secp256r1}, {@code secp384r1}, {@code secp521r1}, {@code x25519},
 * {@code x448}, and, when the {@code tech.kwik.agent15.pqc} module is present, the hybrid groups
 * {@code X25519MLKEM768}, {@code SecP256r1MLKEM768} and {@code SecP384r1MLKEM1024}. A server can restrict the set it
 * offers with {@code TlsServerEngine.addSupportedGroups}.
 *
 * <h2>Getting started</h2>
 * The public API lives in the {@link tech.kwik.agent15.engine} package.
 * <ul>
 *   <li><b>Client:</b> instantiate a {@code TlsClientEngine} with a {@code ClientMessageSender} and a
 *   {@code TlsStatusEventHandler}, then call {@code startHandshake()}. The {@code ClientMessageSender} is the callback
 *   used to actually send handshake messages; the {@code TlsStatusEventHandler} lets the application react to TLS events
 *   needed for the QUIC handshake (for example, when early or handshake secrets become available). Any TLS message
 *   received should be passed to the engine's {@code received} method.</li>
 *   <li><b>Server:</b> instantiate a {@code TlsServerEngine} with a {@code ServerMessageSender}, a
 *   {@code TlsStatusEventHandler}, and the server certificate and its private key. As with the client, any TLS message
 *   received should be passed to the engine, which takes care of sending the necessary messages back to the client.</li>
 * </ul>
 * QUIC's transport-parameters extension is supported by injecting a custom extension parser through the engine API.
 * Session resumption uses a PSK obtained from a {@code NewSessionTicket} message; the server keeps session tickets in an
 * in-memory cache, so a restart invalidates all outstanding tickets. Client authentication with a client certificate is
 * supported by the client engine.
 *
 * <h2>Security</h2>
 * Certificates are validated against the default Java truststore; a custom trust manager can be configured to use other
 * certificate authorities.
 */
module tech.kwik.agent15 {

    exports tech.kwik.agent15;
    exports tech.kwik.agent15.alert;
    exports tech.kwik.agent15.engine;
    exports tech.kwik.agent15.env;
    exports tech.kwik.agent15.extension;
    exports tech.kwik.agent15.handshake;

    // The hybrid key exchange groups of agent15-pqc build on the classical key exchange implementations found here.
    exports tech.kwik.agent15.engine.impl to tech.kwik.agent15.pqc;

    requires at.favre.lib.hkdf;
    requires java.naming;

    // Key exchange groups that core does not implement itself (e.g. the hybrid groups provided by agent15-pqc).
    uses tech.kwik.agent15.engine.KeyExchangeFactory;

    provides tech.kwik.agent15.engine.KeyExchangeFactory with tech.kwik.agent15.engine.impl.KeyExchangeFactoryImpl;
}
