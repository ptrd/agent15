/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.engine.impl;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldReader;
import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.*;
import tech.kwik.agent15.engine.CertificateWithPrivateKey;
import tech.kwik.agent15.engine.ClientMessageSender;
import tech.kwik.agent15.engine.HostnameVerifier;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.handshake.*;
import tech.kwik.agent15.util.ByteUtils;
import tech.kwik.agent15.util.CertificateUtils;
import tech.kwik.agent15.util.FieldSetter;
import tech.kwik.agent15.util.KeyUtils;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x448;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;
import static tech.kwik.agent15.util.CertificateUtils.*;
import static tech.kwik.agent15.util.TestUtils.regardless;

class TlsClientEngineTest {

    // The legacy_session_id_echo a server sends back when the client does not use compatibility mode.
    private static final byte[] EMPTY_SESSION_ID = new byte[0];

    public static final byte[] KEY_EXCHANGE_DATA = ByteUtils.hexToBytes("045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda");

    private TlsClientEngineImpl engine;
    private ECPublicKey publicKey;
    private ClientMessageSender messageSender;
    private TlsConstants.CipherSuite engineCipher;
    private SupportedVersionsExtension mandatorySupportedVersionExtension;
    private KeyShareExtension mandatoryKeyShareExtension;

    @BeforeEach
    void initObjectUnderTest() {
        messageSender = Mockito.mock(ClientMessageSender.class);
        engine = new TlsClientEngineImpl(messageSender, Mockito.mock(TlsStatusEventHandler.class), new KeyExchangeFactoryImpl());
        engine.setServerName("server");
        engineCipher = TLS_AES_128_GCM_SHA256;
        engine.addSupportedCiphers(List.of(engineCipher));

        mandatorySupportedVersionExtension = new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello);
        mandatoryKeyShareExtension = new KeyShareExtension(KEY_EXCHANGE_DATA, secp256r1, TlsConstants.HandshakeType.server_hello);
        publicKey = KeyUtils.generatePublicKey();
    }

    @Test
    void serverHelloShouldContainMandatoryExtensions() throws Exception {
        // Given
        engine.startHandshake();
        ServerHello serverHello = new ServerHello(engineCipher);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloShouldContainSupportedVersionExtension() throws Exception {
        // Given
        engine.startHandshake();
        ServerHello serverHello = new ServerHello(engineCipher, List.of(new ServerPreSharedKeyExtension()));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloSupportedVersionExtensionShouldContainRightVersion() throws Exception {
        // Given
        engine.startHandshake();
        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello);
        FieldSetter.setField(supportedVersionsExtension, supportedVersionsExtension.getClass().getDeclaredField("tlsVersion"), (short) 0x0303);
        ServerHello serverHello = new ServerHello(engineCipher, List.of(new ServerPreSharedKeyExtension(), supportedVersionsExtension));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("version");
    }

    @Test
    void serverHelloShouldContainPreSharedKeyOrKeyShareExtension() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(engineCipher, List.of(mandatorySupportedVersionExtension));  // has neither

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void whenKeyShareExtensionDoesNotContainSupportedNamedGroup() throws Exception {
        // Given
        engine.startHandshake();

        KeyShareExtension keyShareExtension = mock(KeyShareExtension.class);
        when(keyShareExtension.getBytes()).thenReturn(new byte[83]);
        when(keyShareExtension.getKeyShareEntries()).thenReturn(List.of(new KeyShareExtension.KeyShareEntry(TlsConstants.NamedGroup.ffdhe2048, new byte[256])));
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(keyShareExtension, new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void whenKeyShareExtensionDoesNotNamedGroupThatClientOffered() throws Exception {
        // Given
        engine.startHandshake(x25519);

        KeyShareExtension keyShareExtension = mock(KeyShareExtension.class);
        when(keyShareExtension.getBytes()).thenReturn(new byte[83]);
        when(keyShareExtension.getKeyShareEntries()).thenReturn(List.of(new KeyShareExtension.KeyShareEntry(secp256r1, new byte[65])));
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(keyShareExtension, new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloShouldNotContainOtherExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(engineCipher, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                mandatoryKeyShareExtension,
                new ServerNameExtension("server")));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("illegal");
    }

    @Test
    void serverHelloShouldNotContainOtherExtensionsItRecognizes() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(engineCipher, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                mandatoryKeyShareExtension,
                new UnknownExtension()));

        assertThatCode(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void engineAcceptsCorrectServerHello() throws Exception {
        // Given
        engine.startHandshake();
        ServerHello serverHello = createDefaultServerHello();

        assertThatCode(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void serverHelloShouldContainCipherThatClientOffered() throws Exception {
        // Given
        engine.startHandshake();
        TlsConstants.CipherSuite otherCipher = TLS_AES_256_GCM_SHA384;
        ServerHello serverHello = createDefaultServerHello(otherCipher);

        assertThat(otherCipher).isNotEqualTo(engineCipher);
        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("cipher");
    }

    // region hello retry request
    @Test
    void helloRetryRequestShouldLeadToSecondClientHello() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        ClientHello firstClientHello = capturedClientHello();

        // When
        engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.None);

        // Then
        ClientHello secondClientHello = capturedClientHello();
        assertThat(secondClientHello).isNotSameAs(firstClientHello);
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "the client MUST send the same ClientHello without modification, except as follows: (...)"
        assertThat(secondClientHello.getClientRandom()).isEqualTo(firstClientHello.getClientRandom());
        assertThat(secondClientHello.getSessionId()).isEqualTo(firstClientHello.getSessionId());
        assertThat(secondClientHello.getCipherSuites()).isEqualTo(firstClientHello.getCipherSuites());
    }

    @Test
    void secondClientHelloShouldContainKeyShareForSelectedGroup() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        assertThat(keyShareGroupsOf(capturedClientHello())).containsExactly(secp256r1);

        // When
        engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.None);

        // Then
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
        // "the client MUST replace the original "key_share" extension with one containing only a new KeyShareEntry for
        //  the group indicated in the selected_group field of the triggering HelloRetryRequest."
        assertThat(keyShareGroupsOf(capturedClientHello())).containsExactly(x25519);
    }

    @Test
    void secondClientHelloShouldEchoCookieFromHelloRetryRequest() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        // When
        engine.received(createHelloRetryRequest(x25519, ByteUtils.hexToBytes("cafebabe")), ProtectionKeysType.None);

        // Then
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
        // "the client MUST copy the contents of the extension received in the HelloRetryRequest into a "cookie"
        //  extension in the new ClientHello."
        CookieExtension cookie = (CookieExtension) extensionOfType(capturedClientHello(), CookieExtension.class);
        assertThat(cookie.getCookie()).isEqualTo(ByteUtils.hexToBytes("cafebabe"));
    }

    @Test
    void whenHelloRetryRequestHasNoKeyShareTheOriginalKeyShareIsRetained() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        // When: a hello retry request with a cookie only (e.g. to have the client prove reachability)
        engine.received(new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                List.of(mandatorySupportedVersionExtension, new CookieExtension(ByteUtils.hexToBytes("cafebabe")))),
                ProtectionKeysType.None);

        // Then
        assertThat(keyShareGroupsOf(capturedClientHello())).containsExactly(secp256r1);
    }

    @Test
    void earlyDataExtensionShouldBeRemovedFromSecondClientHello() throws Exception {
        // Given
        engine.add(new EarlyDataExtension());
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        assertThat(capturedClientHello().getExtensions()).anyMatch(ext -> ext instanceof EarlyDataExtension);

        // When
        engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.None);

        // Then
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "Removing the "early_data" extension (Section 4.2.10) if one was present."
        assertThat(capturedClientHello().getExtensions()).noneMatch(ext -> ext instanceof EarlyDataExtension);
    }

    @Test
    void secondHelloRetryRequestShouldLeadToUnexpectedMessageAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.None);

        assertThatThrownBy(() ->
                // When
                engine.received(createHelloRetryRequest(secp256r1), ProtectionKeysType.None))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void helloRetryRequestSelectingGroupThatWasNotOfferedShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When: x448 is supported by this implementation, but was not offered
                engine.received(createHelloRetryRequest(x448), ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("not offered");
    }

    @Test
    void helloRetryRequestSelectingUnknownGroupShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        // A key share extension selecting group 0x6666, which is not a group this implementation knows.
        String hrrInHex = ("02 000000  0303 CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C  00  1301   00"
                + "000c   002b00020304        00330002 6666").replaceAll(" ", "");
        byte[] data = setTlsMsgLength(ByteUtils.hexToBytes(hrrInHex));
        HandshakeMessage hrr = ServerHello.parse(ByteBuffer.wrap(data), data.length);

        assertThatThrownBy(() ->
                // When
                engine.received(hrr, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void helloRetryRequestSelectingGroupAlreadyUsedForKeyShareShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When
                engine.received(createHelloRetryRequest(secp256r1), ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("already used");
    }

    @Test
    void helloRetryRequestThatChangesNothingShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When: neither a key share nor a cookie, so the client hello would not change
                engine.received(new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                        List.of(mandatorySupportedVersionExtension)), ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("not result in any change");
    }

    @Test
    void helloRetryRequestWithCipherThatWasNotOfferedShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When
                engine.received(new HelloRetryRequest(TLS_CHACHA20_POLY1305_SHA256, EMPTY_SESSION_ID,
                        List.of(mandatorySupportedVersionExtension, new KeyShareExtension(x25519))),
                        ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("cipher");
    }

    @Test
    void helloRetryRequestWithIncorrectSessionIdEchoShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.setCompatibilityMode(true);
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When
                engine.received(new HelloRetryRequest(engineCipher, new byte[32],
                        List.of(mandatorySupportedVersionExtension, new KeyShareExtension(x25519))),
                        ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("legacy_session_id_echo");
    }

    @Test
    void helloRetryRequestWithoutSupportedVersionsExtensionShouldLeadToMissingExtensionAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When
                engine.received(new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                        List.of(new KeyShareExtension(x25519))), ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void helloRetryRequestWithExtensionThatIsNotAllowedShouldLeadToIllegalParameterAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When: a pre_shared_key extension is allowed in CH and SH, but not in a HelloRetryRequest
                engine.received(new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                        List.of(mandatorySupportedVersionExtension, new KeyShareExtension(x25519),
                                new ServerPreSharedKeyExtension(0))),
                        ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("illegal extension");
    }

    @Test
    void helloRetryRequestWithUnrequestedExtensionShouldLeadToUnsupportedExtensionAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When: an extension the client did not offer (and that is not the cookie extension)
                engine.received(new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                        List.of(mandatorySupportedVersionExtension, new KeyShareExtension(x25519),
                                new UnknownExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes("f0f000020000"))))),
                        ProtectionKeysType.None))
                // Then
                .isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void helloRetryRequestShouldNotBeAcceptedAfterServerHello() throws Exception {
        // Given
        handshakeUpToEncryptedExtensions();

        assertThatThrownBy(() ->
                // When
                engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.None))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void helloRetryRequestWithIncorrectProtectionLevelShouldLeadToUnexpectedMessageAlert() throws Exception {
        // Given
        engine.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));

        assertThatThrownBy(() ->
                // When
                engine.received(createHelloRetryRequest(x25519), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    // endregion

    @Test
    void whenServerHelloContainsCipherThatClientNotEvenKnows() throws Exception {
        // Given
        engine.startHandshake();

        // Server Hello       v3  random (32 bytes)                                      session_id cipher: 0x1313
        //                                                                                        | |   extensions
        String hex = "0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d7425740418500131300004f002b00020304003300450017004104ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e";
        byte[] data = ByteUtils.hexToBytes(hex);

        ServerHello serverHelloWithUnknownCipher = (ServerHello) ServerHello.parse(ByteBuffer.wrap(data), data.length);

        assertThatThrownBy(() ->
                // When
                engine.received(serverHelloWithUnknownCipher, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("cipher");
    }

    @Test
    void afterProperServerHelloSelectedCipherIsAvailable() throws Exception {
        // Given
        engine.startHandshake();
        assertThatThrownBy(() ->
                engine.getSelectedCipher()
        ).isInstanceOf(IllegalStateException.class);

        // When
        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void afterProperServerHelloTrafficSecretsAreAvailable() throws Exception {
        // Given
        engine.startHandshake();

        // When
        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // Then
        Assertions.assertThat(engine.getClientHandshakeTrafficSecret())
                .isNotNull()
                .hasSizeGreaterThan(12);
    }

    @Test
    void secondServerHelloShouldBeIgnored() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello1 = createDefaultServerHello();
        engine.received(serverHello1, ProtectionKeysType.None);

        // When
        ServerHello serverHello2 = createDefaultServerHello(TLS_CHACHA20_POLY1305_SHA256);
        regardless(() ->
                engine.received(serverHello2, ProtectionKeysType.None)
        );

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(serverHello1.getCipherSuite());
    }

    @Test
    void encryptedExtensionsShouldNotBeReceivedBeforeServerHello() throws Exception {
        // Given
        engine.startHandshake();

        assertThatThrownBy(() ->
                // Wen
                engine.received(new EncryptedExtensions(emptyList()), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainExtensionNotOfferedByClient() throws Exception {
        // Given
        engine.startHandshake();
        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        assertThatThrownBy(() ->
                // When
                engine.received(new EncryptedExtensions(List.of(new DummyExtension())), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainDuplicateTypes() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        assertThatThrownBy(() ->
                // When
                engine.received(new EncryptedExtensions(List.of(
                        new ServerNameExtension("server"),
                        new ServerNameExtension("server")
                )), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloShouldNotContainDuplicateExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello(List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloPreSharedKeyExtensionSelectedIdentityMustBeZero() throws Exception {
        // Given
        startHandshakeWithPsk();
        // ServerPreSharedKeyExtension with selectedIdentity = 1 is invalid: the client offered only one PSK (index 0)
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11
        // "the server's selected_identity MUST be within the range supplied by the client"
        ServerHello serverHello = createDefaultServerHello(List.of(new ServerPreSharedKeyExtension(1)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloLegacySessionIdEchoMustMatchClientHelloSessionId() throws Exception {
        // Given: compatibility mode causes the client to send a random 32-byte legacy_session_id.
        engine.setCompatibilityMode(true);
        engine.startHandshake();

        // Build a ServerHello whose legacy_session_id_echo is 32 zero bytes — virtually guaranteed not
        // to match the random value the client just sent in ClientHello.
        //                              type    length legacy_v  random                                                            sid_len sid (32 zero bytes)                                              cipher cmp  extensions...
        String serverHelloHex = ("02 000097 0303 1219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185 20 0000000000000000000000000000000000000000000000000000000000000000 1301 00").replaceAll(" ", "");
        String mandatoryExtensions = ("004f 002b00020304 003300450017004104ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e").replaceAll(" ", "");
        byte[] data = ByteUtils.hexToBytes(serverHelloHex + mandatoryExtensions);
        ServerHello serverHello = (ServerHello) ServerHello.parse(ByteBuffer.wrap(data), data.length);

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloPreSharedKeyExtensionRequiresClientToHaveOfferedPsk() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.1.4
        // "Upon receiving such an extension [that the endpoint did not request], an endpoint MUST abort the handshake
        //  with an "unsupported_extension" alert."
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2
        // "Implementations MUST NOT send extension responses if the remote endpoint did not send the corresponding
        //  extension requests..."
        // The client started a handshake without offering any PSK (no setNewSessionTicket call), so the server
        // including a pre_shared_key in ServerHello is a protocol violation that the client MUST reject.

        // Given
        engine.startHandshake();
        ServerHello serverHello = createDefaultServerHello(List.of(new ServerPreSharedKeyExtension(0)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(ErrorAlert.class);
    }

    @Test
    void serverHelloThatAcceptsPskWithoutKeyShareMustBeRejectedWhenClientOfferedDheOnly() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
        // "psk_dhe_ke: PSK with (EC)DHE key establishment. In this mode, the client and server MUST supply "key_share"
        //  values (...)."
        // The client only ever offers psk_dhe_ke (PSKwithDHE), so if the server accepts the PSK but omits the key_share
        // extension, it is silently downgrading to non-forward-secret pure PSK (psk_ke). The client MUST refuse this.

        // Given: client offered a PSK (and, implicitly, only the psk_dhe_ke mode)
        startHandshakeWithPsk();
        // ServerHello accepts the PSK but contains no key_share extension.
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                mandatorySupportedVersionExtension,
                new ServerPreSharedKeyExtension(0)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(ErrorAlert.class);
    }

    @Test
    void serverHelloThatAcceptsPskMustSelectCipherWithSameHashAsPsk() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11
        // "Clients MUST verify that the server's selected_identity is within the range supplied by the client, that
        //  the server selected a cipher suite indicating a Hash associated with the PSK (...). If these values are
        //  not consistent, the client MUST abort the handshake with an "illegal_parameter" alert."

        // Given: client offered a PSK established with TLS_AES_128_GCM_SHA256 (SHA-256), while also supporting a SHA-384 cipher
        engine.addSupportedCiphers(List.of(TLS_AES_256_GCM_SHA384));
        startHandshakeWithPsk();
        // ServerHello accepts the PSK, but selects a cipher whose hash (SHA-384) differs from the PSK's hash (SHA-256).
        ServerHello serverHello = createDefaultServerHello(TLS_AES_256_GCM_SHA384, List.of(new ServerPreSharedKeyExtension(0)));

        assertThatThrownBy(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloThatAcceptsPskMaySelectDifferentCipherWithSameHash() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11
        // "Each PSK is associated with a single Hash algorithm."
        // The consistency requirement is on the hash, not on the exact cipher suite: a server may accept a PSK
        // established with TLS_AES_128_GCM_SHA256 while selecting TLS_CHACHA20_POLY1305_SHA256 (both SHA-256).

        // Given: client offered a PSK established with TLS_AES_128_GCM_SHA256, while also supporting another SHA-256 cipher
        engine.addSupportedCiphers(List.of(TLS_CHACHA20_POLY1305_SHA256));
        startHandshakeWithPsk();
        // ServerHello accepts the PSK and selects the other cipher with the same (SHA-256) hash.
        ServerHello serverHello = createDefaultServerHello(TLS_CHACHA20_POLY1305_SHA256, List.of(new ServerPreSharedKeyExtension(0)));

        assertThatCode(() ->
                // When
                engine.received(serverHello, ProtectionKeysType.None))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void certificateRequestShouldNotContainDuplicateExtensions() throws Exception {
        // Given
        handshakeUpToCertificate();

        CertificateRequestMessage certificateRequest = new CertificateRequestMessage(new SignatureAlgorithmsExtension(rsa_pss_rsae_sha256));
        FieldSetter.setField(certificateRequest, certificateRequest.getClass().getDeclaredField("extensions"),
                List.of(new SignatureAlgorithmsExtension(rsa_pss_rsae_sha256), new SignatureAlgorithmsExtension(ecdsa_secp521r1_sha512)));

        assertThatThrownBy(() ->
                // When
                engine.received(certificateRequest, ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void certificateMessageShouldNotBeReceivedBeforeEncryptedExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // Then
        assertThatThrownBy(() ->
                // When, no Encrypted Extensions Message received, but
                engine.received(new CertificateMessage(), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void serverCertificateMessageRequestContextShouldBeEmpty() throws Exception {
        // Given
        handshakeUpToCertificate();

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[300]);
        CertificateMessage certificateMessage = new CertificateMessage(new byte[4], cert);

        assertThatThrownBy(() ->
                // When
                engine.received(certificateMessage, ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverCertificateMessageShouldAlwaysContainAtLeastOneCertificate() throws Exception {
        // Given
        handshakeUpToCertificate();

        CertificateMessage certificateMessage = new CertificateMessage();
        byte[] emptyCertificateMessageData = ByteUtils.hexToBytes("0b000009" + "00" + "000005" + "0000000000");
        certificateMessage.parse(ByteBuffer.wrap(emptyCertificateMessageData));

        assertThatThrownBy(() ->
                // When
                engine.received(certificateMessage, ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void certificateVerifyShouldNotBeReceivedBeforeCertificateMessage() throws Exception {
        // Given
        handshakeUpToCertificate();

        assertThatThrownBy(() ->
                // When, no Certificate Message received, but
                engine.received(new CertificateVerifyMessage(), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void certificateVerifySignatureSchemeShouldMatch() throws Exception {
        // Given
        handshakeUpToCertificate(List.of(TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256), false);
        Certificate certificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        engine.received(new CertificateMessage((X509Certificate) certificate), ProtectionKeysType.Handshake);

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, new byte[0]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void validSignatureShouldPassValidation() throws Exception {
        // Given
        engine.setHostnameVerifier(createNoOpHostnameVerifier());
        engine.setTrustManager(createNoOpTrustManager());
        byte[] validSignature = createServerSignature();

        handshakeUpToCertificate();

        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        assertThatCode(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void whenSignatureVerificationFailsHandshakeShouldBeTerminatedWithDecryptError() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, new byte[256]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void testVerifySignature() throws Exception {
        byte[] signature = createServerSignature();

        Certificate certificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);

        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0x01);

        boolean verified = engine.verifySignature(signature, rsa_pss_rsae_sha256, certificate, hash);

        assertThat(verified).isTrue();
    }

    @Test
    void verifySignatureWithWrongEcCurveShouldThrowIllegalParameter() throws Exception {
        // Given: a P-384 certificate, but the scheme claims P-256 (ecdsa_secp256r1_sha256)
        Certificate p384Certificate = CertificateUtils.inflateCertificate(encodedSampleEcdsa384Certificate);
        byte[] hash = new byte[32];

        assertThatThrownBy(() ->
                // When
                engine.verifySignature(new byte[0], ecdsa_secp256r1_sha256, p384Certificate, hash))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void unknownCertificateShouldAbortTls() throws Exception {
        // Given
        byte[] validSignature = createServerSignature();
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(BadCertificateAlert.class);
    }

    @Test
    void certificateSignedByTrustedCaShouldBeAccepted() throws Exception {
        // Given
        engine.setTrustManager(createTrustManagerFor(CertificateUtils.inflateCertificate(encodedSampleCA1)));
        X509Certificate serverCertificate = inflateCertificate(encodedCA1SignedCert);
        engine.setServerName("sample1.com");
        byte[] validSignature = createServerSignatureFromPrivateKey(encodedCA1SignedCertPrivateKey);

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(serverCertificate), ProtectionKeysType.Handshake);

        assertThatCode(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void certificateNotSignedByTrustedCaShouldBeAccepted() throws Exception {
        // Given
        engine.setTrustManager(createTrustManagerFor(CertificateUtils.inflateCertificate(encodedSampleCA1)));  // CA_1
        X509Certificate serverCertificate = inflateCertificate(encodedCA2SignedCert);    // Cert signed by CA_2, not CA_1!
        engine.setServerName("sample2.com");
        byte[] validSignature = createServerSignatureFromPrivateKey(encodedCA2SignedCertPrivateKey);

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(serverCertificate), ProtectionKeysType.Handshake);

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(BadCertificateAlert.class);
    }
    
    private X509TrustManager createTrustManagerFor(X509Certificate caCertificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        keyStore.setCertificateEntry("ca", caCertificate);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(keyStore);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    @Test
    void certificateWithoutMatchingServerNameShouldAbortTls() throws Exception {
        // Given
        engine.setHostnameVerifier(createAlwaysRefusingVerifier());
        engine.setTrustManager(createNoOpTrustManager());

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        byte[] validSignature = createServerSignature();
        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void clearingHostnameVerifierDoesNotBypassDefaultVerification() throws Exception {
        // Given
        engine.setTrustManager(createNoOpTrustManager());
        byte[] validSignature = createServerSignature();

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        // When
        engine.setHostnameVerifier(null);
        assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void finisedMessageShouldNotBeReceivedBeforeCertificateVerify() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        assertThatThrownBy(() ->
                // When, no Certificate Verify Message received
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void withPskAcceptedFinisedMessageShouldFollowEncryptedExentions() throws Exception {
        // Given
        handshakeUpToCertificate(true);

        assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(DecryptErrorAlert.class);  // And not UnexpectedMessageAlert
    }

    @Test
    void withPskAcceptedFinisedMessageShouldNotBeReceivedBeforeEncryptedExentions() throws Exception {
        // Given
        handshakeUpToEncryptedExtensions(true);

        assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void incorrectServerFinishedShouldAbortTls() throws Exception {
        handshakeUpToFinished();

        FinishedMessage finishedMessage = new FinishedMessage(new byte[256]);

        assertThatThrownBy(() ->
                // When
                engine.received(finishedMessage, ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void engineShouldSendClientFinishedWhenHandshakeDone() throws Exception {
        handshakeUpToFinished();

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngineImpl stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }

    @Test
    void clientEngineShouldKeepOnlyTheLastTwoNewSessionTickets() throws Exception {
        // Given: a completed handshake, so resumption secrets are available and NewSessionTicketMessages can be processed.
        handshakeUpToFinished();
        TlsClientEngineImpl completedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(completedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        completedEngine.received(new FinishedMessage(new byte[32]), ProtectionKeysType.Handshake);

        // When: the server sends three NewSessionTicketMessages
        NewSessionTicketMessage ticket1 = new NewSessionTicketMessage(3600, 0x01010101L, new byte[] { 1 }, new byte[] { 0x0a });
        NewSessionTicketMessage ticket2 = new NewSessionTicketMessage(3600, 0x02020202L, new byte[] { 2 }, new byte[] { 0x0b });
        NewSessionTicketMessage ticket3 = new NewSessionTicketMessage(3600, 0x03030303L, new byte[] { 3 }, new byte[] { 0x0c });
        completedEngine.received(ticket1, ProtectionKeysType.Application);
        completedEngine.received(ticket2, ProtectionKeysType.Application);
        completedEngine.received(ticket3, ProtectionKeysType.Application);

        // Then: only the last two tickets are retained; the oldest is evicted.
        List<NewSessionTicket> tickets = completedEngine.getNewSessionTickets();
        assertThat(tickets).hasSize(2);
        assertThat(tickets).extracting(NewSessionTicket::getTicketAgeAdd)
                .containsExactly(0x02020202L, 0x03030303L);
    }

    @Test
    void newSessionTicketWithZeroLifetimeShouldBeDiscarded() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
        // "ticket_lifetime: (...) The value of zero indicates that the ticket should be discarded immediately."

        // Given: a completed handshake, so resumption secrets are available and NewSessionTicketMessages can be processed.
        handshakeUpToFinished();
        TlsClientEngineImpl completedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(completedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        completedEngine.received(new FinishedMessage(new byte[32]), ProtectionKeysType.Handshake);

        // When: the server sends a NewSessionTicketMessage with a zero ticket lifetime
        int ticketLifetime = 0;
        long ticketAgeAdd = 0x01010101L;
        byte[] ticketNonce = { 1 };
        byte[] ticket = { 0x0a };
        NewSessionTicketMessage zeroLifetimeTicket = new NewSessionTicketMessage(ticketLifetime, ticketAgeAdd, ticketNonce, ticket);
        completedEngine.received(zeroLifetimeTicket, ProtectionKeysType.Application);

        // Then: the ticket is not retained
        assertThat(completedEngine.getNewSessionTickets()).isEmpty();
    }

    @Test
    void startHandshakeWithExpiredTicketShouldFallBackToFullHandshake() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
        // "Clients MUST NOT cache tickets for longer than 7 days, regardless of the ticket_lifetime, and MAY delete
        //  tickets earlier based on local policy."
        // As ticket_lifetime is capped at 7 days (604800 seconds, enforced when parsing NewSessionTicket messages),
        // not offering any ticket whose lifetime has passed implements this requirement.

        // Given: a ticket that was created two hours ago with a lifetime of one hour, so it has expired.
        NewSessionTicket expiredTicket = createNewSessionTicket();
        when(expiredTicket.getTicketCreationDate()).thenReturn(new Date(System.currentTimeMillis() - 7200_000));
        when(expiredTicket.getTicketLifeTime()).thenReturn(3600);
        engine.setNewSessionTicket(expiredTicket);

        // When
        engine.startHandshake();

        // Then: the expired ticket is not offered (no pre_shared_key extension), i.e. a full handshake is performed.
        ArgumentCaptor<ClientHello> messageCaptor = ArgumentCaptor.forClass(ClientHello.class);
        verify(messageSender).send(messageCaptor.capture());
        assertThat(messageCaptor.getValue().getExtensions())
                .noneMatch(extension -> extension instanceof ClientHelloPreSharedKeyExtension);
    }

    @Test
    void certificateRequestMessageShouldNotBeReceivedBeforeEncryptedExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension()), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void certificateRequestMessageShouldNotBeReceivedAfterCertificate() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate)), ProtectionKeysType.Handshake);

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension()), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void withoutClientCertificateClientAuthLeadsToAdditionalCertificateMessageBeforeFinished() throws Exception {
        // Given
        handshakeUpToFinished(List.of(rsa_pss_rsae_sha256), true, null);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngineImpl stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        // When
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        // Then
        Mockito.verify(messageSender).send(ArgumentMatchers.any(CertificateMessage.class));
        Mockito.verify(messageSender, never()).send(ArgumentMatchers.any(CertificateVerifyMessage.class));
        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }

    @Test
    void withClientCertificateClientAuthLeadsToAdditionalCertificateMessageAndVerifyBeforeFinished() throws Exception {
        // Given
        X509Certificate clientCertificate = CertificateUtils.getTestCertificate();
        PrivateKey privateKey = CertificateUtils.getPrivateKey();
        engine.setClientCertificateCallback(arg -> new CertificateWithPrivateKey(clientCertificate, privateKey));

        handshakeUpToFinished(List.of(rsa_pss_rsae_sha256), true, null);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngineImpl stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        // When
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        // Then
        Mockito.verify(messageSender).send(ArgumentMatchers.any(CertificateMessage.class));
        Mockito.verify(messageSender).send(ArgumentMatchers.any(CertificateVerifyMessage.class));
        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }

    @Test
    void unsupportedNamedGroupLeadsToException() throws Exception {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(TlsConstants.NamedGroup.ffdhe8192))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ffdhe8192");
    }

    @Test
    void unsupportedSignatureSchemeLeadsToException() throws Exception {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(secp256r1,
                        List.of(rsa_pss_rsae_sha256, rsa_pkcs1_sha1)))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rsa_pkcs1_sha1");
    }

    @Test
    void certificateRequestMessageShouldContainSignatureAlgorithmsExtension() throws Exception {
        // Given
        handshakeUpToCertificate();

        assertThatThrownBy(() ->
                // When
                engine.received(new CertificateRequestMessage(new CertificateAuthoritiesExtension(new X500Principal("CN=dummy"))), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void signatureUsedForClientAuthCertVerifyShouldSelectedFromWhatServerOffers() throws Exception {
        // Given
        X509Certificate clientCertificate = CertificateUtils.getTestCertificate();
        PrivateKey privateKey = CertificateUtils.getPrivateKey();
        engine.setClientCertificateCallback(arg -> new CertificateWithPrivateKey(clientCertificate, privateKey));

        handshakeUpToFinished(List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384), true, rsa_pss_rsae_sha384);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngineImpl stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        // When
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        // Then
        ArgumentCaptor<CertificateVerifyMessage> messageCaptor = ArgumentCaptor.forClass(CertificateVerifyMessage.class);
        verify(messageSender).send(messageCaptor.capture());
        assertThat(messageCaptor.getValue().getSignatureScheme()).isEqualTo(rsa_pss_rsae_sha384);
    }


    @Test
    void clientHelloSentByEngineOffersTheGivenSupportedGroups() throws Exception {
        // When
        engine.startHandshake(secp256r1, List.of(secp256r1, x448, x25519), List.of(rsa_pss_rsae_sha256));

        // Then
        ArgumentCaptor<ClientHello> messageCaptor = ArgumentCaptor.forClass(ClientHello.class);
        verify(messageSender).send(messageCaptor.capture());

        SupportedGroupsExtension supportedGroups = (SupportedGroupsExtension) messageCaptor.getValue().getExtensions().stream()
                .filter(ext -> ext instanceof SupportedGroupsExtension)
                .findFirst().orElseThrow();
        assertThat(supportedGroups.getNamedGroups()).containsExactly(secp256r1, x448, x25519);
    }

    @Test
    void whenSupportedGroupsAreGivenKeyShareStillUsesTheGivenNamedGroupOnly() throws Exception {
        // When
        engine.startHandshake(x25519, List.of(secp256r1, x448, x25519), List.of(rsa_pss_rsae_sha256));

        // Then
        ArgumentCaptor<ClientHello> messageCaptor = ArgumentCaptor.forClass(ClientHello.class);
        verify(messageSender).send(messageCaptor.capture());

        KeyShareExtension keyShare = (KeyShareExtension) messageCaptor.getValue().getExtensions().stream()
                .filter(ext -> ext instanceof KeyShareExtension)
                .findFirst().orElseThrow();
        assertThat(keyShare.getKeyShareEntries())
                .extracting(KeyShareExtension.KeyShareEntry::getNamedGroup)
                .containsExactly(x25519);
    }

    @Test
    void whenNoSupportedGroupsAreGivenOnlyTheKeyShareGroupIsOffered() throws Exception {
        // When
        engine.startHandshake(x25519, List.of(rsa_pss_rsae_sha256));

        // Then
        ArgumentCaptor<ClientHello> messageCaptor = ArgumentCaptor.forClass(ClientHello.class);
        verify(messageSender).send(messageCaptor.capture());

        SupportedGroupsExtension supportedGroups = (SupportedGroupsExtension) messageCaptor.getValue().getExtensions().stream()
                .filter(ext -> ext instanceof SupportedGroupsExtension)
                .findFirst().orElseThrow();
        assertThat(supportedGroups.getNamedGroups()).containsExactly(x25519);
    }

    @Test
    void supportedGroupsNotContainingTheKeyShareGroupLeadsToException() {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(secp256r1, List.of(x448, x25519), List.of(rsa_pss_rsae_sha256)))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secp256r1");
    }

    @Test
    void unsupportedGroupInSupportedGroupsLeadsToException() {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(secp256r1, List.of(secp256r1, TlsConstants.NamedGroup.ffdhe8192), List.of(rsa_pss_rsae_sha256)))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ffdhe8192");
    }

    @Test
    void emptySupportedGroupsLeadsToException() {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(secp256r1, Collections.emptyList(), List.of(rsa_pss_rsae_sha256)))
                // Then
                .isInstanceOf(IllegalArgumentException.class);
    }

    private void startHandshakeWithPsk() throws Exception {
        engine.setNewSessionTicket(createNewSessionTicket());
        engine.startHandshake();
    }

    private NewSessionTicket createNewSessionTicket() {
        NewSessionTicket newSessionTicket = mock(NewSessionTicket.class);
        when(newSessionTicket.getCipher()).thenReturn(TLS_AES_128_GCM_SHA256);
        when(newSessionTicket.getTicketCreationDate()).thenReturn(new Date());
        when(newSessionTicket.getTicketLifeTime()).thenReturn(3600);
        when(newSessionTicket.getSessionTicketIdentity()).thenReturn(new byte[32]);
        return newSessionTicket;
    }


    @Test
    void certificateWithSecp384r1KeyShouldSupportEcdsaSecp384r1Sha384() throws Exception {
        // Given
        X509Certificate cert = CertificateUtils.inflateCertificate(encodedSampleEcdsa384Certificate);

        // When/Then: the cert's public key is on secp384r1, so it must support ecdsa_secp384r1_sha384
        assertThat(engine.keyMatchesSignatureAlgorithm(cert.getPublicKey(), ecdsa_secp384r1_sha384)).isTrue();
    }

    @Test
    void certificateWithSecp384r1KeyShouldNotSupportEcdsaSecp256r1Sha256() throws Exception {
        // Given
        X509Certificate cert = CertificateUtils.inflateCertificate(encodedSampleEcdsa384Certificate);

        // When/Then: the cert's public key is on secp384r1, so it must NOT support ecdsa_secp256r1_sha256
        // (a P-384 key cannot produce a P-256 signature)
        assertThat(engine.keyMatchesSignatureAlgorithm(cert.getPublicKey(), ecdsa_secp256r1_sha256)).isFalse();
    }

    @Test
    void certificateWithSecp521r1KeyShouldSupportEcdsaSecp521r1Sha512() throws Exception {
        // Given
        X509Certificate cert = CertificateUtils.inflateCertificate(encodedSampleEcdsa512Certificate);

        // When/Then
        assertThat(engine.keyMatchesSignatureAlgorithm(cert.getPublicKey(), ecdsa_secp521r1_sha512)).isTrue();
    }

    private HelloRetryRequest createHelloRetryRequest(TlsConstants.NamedGroup selectedGroup) {
        return new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                List.of(mandatorySupportedVersionExtension, new KeyShareExtension(selectedGroup)));
    }

    private HelloRetryRequest createHelloRetryRequest(TlsConstants.NamedGroup selectedGroup, byte[] cookie) {
        return new HelloRetryRequest(engineCipher, EMPTY_SESSION_ID,
                List.of(mandatorySupportedVersionExtension, new KeyShareExtension(selectedGroup), new CookieExtension(cookie)));
    }

    /**
     * Returns the last client hello that the engine passed to the message sender.
     */
    private ClientHello capturedClientHello() throws Exception {
        ArgumentCaptor<ClientHello> captor = ArgumentCaptor.forClass(ClientHello.class);
        verify(messageSender, atLeastOnce()).send(captor.capture());
        return captor.getValue();
    }

    private List<TlsConstants.NamedGroup> keyShareGroupsOf(ClientHello clientHello) {
        return ((KeyShareExtension) extensionOfType(clientHello, KeyShareExtension.class)).getKeyShareEntries().stream()
                .map(KeyShareExtension.KeyShareEntry::getNamedGroup)
                .collect(Collectors.toList());
    }

    private Extension extensionOfType(ClientHello clientHello, Class<? extends Extension> type) {
        return clientHello.getExtensions().stream()
                .filter(type::isInstance)
                .findFirst()
                .orElseThrow(() -> new AssertionError("ClientHello does not contain a " + type.getSimpleName()));
    }

    private byte[] setTlsMsgLength(byte[] messageBytes) {
        int bodyLength = messageBytes.length - 4;
        messageBytes[1] = (byte) (bodyLength >> 16);
        messageBytes[2] = (byte) (bodyLength >> 8);
        messageBytes[3] = (byte) bodyLength;
        return messageBytes;
    }

    private ServerHello createDefaultServerHello() {
        return createDefaultServerHello(engineCipher, emptyList());
    }

    private ServerHello createDefaultServerHello(TlsConstants.CipherSuite cipherSuit) {
        return createDefaultServerHello(cipherSuit, emptyList());
    }

    private ServerHello createDefaultServerHello(List<Extension> additionalExtensions) {
        return createDefaultServerHello(TLS_AES_128_GCM_SHA256, additionalExtensions);
    }

    private ServerHello createDefaultServerHello(TlsConstants.CipherSuite cipherSuite, List<Extension> additionalExtensions) {
        List<Extension> extensions = new ArrayList<>();
        extensions.addAll(List.of(
                mandatorySupportedVersionExtension,
                mandatoryKeyShareExtension));
        extensions.addAll(additionalExtensions);
        return new ServerHello(cipherSuite, extensions);
    }

    private void handshakeUpToEncryptedExtensions() throws Exception {
        handshakeUpToEncryptedExtensions(List.of(rsa_pss_rsae_sha256), false);
    }

    private void handshakeUpToEncryptedExtensions(boolean withPsk) throws Exception {
        handshakeUpToEncryptedExtensions(List.of(rsa_pss_rsae_sha256), withPsk);
    }

    private void handshakeUpToEncryptedExtensions(List<TlsConstants.SignatureScheme> signatureSchemes, boolean withPsk) throws Exception {
        if (withPsk) {
            engine.setNewSessionTicket(createNewSessionTicket());
        }
        engine.startHandshake(secp256r1, signatureSchemes);

        ServerHello serverHello = createDefaultServerHello(withPsk? List.of(new ServerPreSharedKeyExtension(0)): emptyList());
        engine.received(serverHello, ProtectionKeysType.None);
        Mockito.clearInvocations(messageSender);
    }

    private void handshakeUpToCertificate() throws Exception {
        handshakeUpToCertificate(List.of(rsa_pss_rsae_sha256), false);
    }

    private void handshakeUpToCertificate(boolean withPsk) throws Exception {
        handshakeUpToCertificate(List.of(rsa_pss_rsae_sha256), withPsk);
    }

    private void handshakeUpToCertificate(List<TlsConstants.SignatureScheme> signatureSchemes, boolean withPsk) throws Exception {
        handshakeUpToEncryptedExtensions(signatureSchemes, withPsk);

        TranscriptHash transcriptHash = (TranscriptHash) Mockito.spy(new FieldReader(engine, engine.getClass().getDeclaredField("transcriptHash")).read());
        Mockito.doReturn(ByteUtils.hexToBytes("0101010101010101010101010101010101010101010101010101010101010101")).when(transcriptHash).getServerHash(ArgumentMatchers.argThat(t -> t == TlsConstants.HandshakeType.certificate));
        FieldSetter.setField(engine, engine.getClass().getDeclaredField("transcriptHash"), transcriptHash);

        engine.received(new EncryptedExtensions(), ProtectionKeysType.Handshake);
    }

    private void handshakeUpToFinished() throws Exception {
        handshakeUpToFinished(List.of(rsa_pss_rsae_sha256), false, null);
    }

    private void handshakeUpToFinished(List<TlsConstants.SignatureScheme> signatureSchemes, boolean requestClientCert,
                                       TlsConstants.SignatureScheme clientAuthRequiredSignatureScheme) throws Exception {
        handshakeUpToCertificate(signatureSchemes, false);
        if (requestClientCert) {
            if (clientAuthRequiredSignatureScheme == null) {
                clientAuthRequiredSignatureScheme = rsa_pss_rsae_sha256;
            }
            engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension(clientAuthRequiredSignatureScheme)), ProtectionKeysType.Handshake);
        }
        X509Certificate certificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        byte[] validSignature = createServerSignature();
        engine.setTrustManager(createNoOpTrustManager());
        engine.setHostnameVerifier(createNoOpHostnameVerifier());
        engine.received(new CertificateMessage(certificate), ProtectionKeysType.Handshake);
        engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake);
    }

    private byte[] createServerSignature() throws Exception {
        return createServerSignatureFromPrivateKey(encodedKwikDotTechRsaCertificatePrivateKey);
    }

    private byte[] createServerSignatureFromPrivateKey(String encodedPrivateKey) throws Exception {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3
        // "For example, if the transcript hash was 32 bytes of 01 (this length would make sense for SHA-256),
        // the content covered by the digital signature for a server CertificateVerify would be:"
        String content = "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
                + "544c5320312e332c2073657276657220436572746966696361746556657269667900"
                + "0101010101010101010101010101010101010101010101010101010101010101";
        byte[] messageBytes = ByteUtils.hexToBytes(content);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        Signature signatureAlgorithm = Signature.getInstance("RSASSA-PSS");
        signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        signatureAlgorithm.initSign(privateKey);
        signatureAlgorithm.update(messageBytes);
        byte[] digitalSignature = signatureAlgorithm.sign();
        return digitalSignature;
    }

    private HostnameVerifier createNoOpHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, X509Certificate serverCertificate) {
                return true;
            }
        };
    }

    private HostnameVerifier createAlwaysRefusingVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, X509Certificate serverCertificate) {
                return false;
            }
        };
    }

    X509TrustManager createNoOpTrustManager() {
        return new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
            }
        };
    }

    static class DummyExtension extends Extension {

        @Override
        public int getType() {
            return -1;
        }

        @Override
        public byte[] getBytes() {
            return new byte[0];
        }
    }
}