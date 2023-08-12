/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.tls.handshake;

import net.luminis.tls.*;
import net.luminis.tls.alert.*;
import net.luminis.tls.extension.*;
import net.luminis.tls.util.ByteUtils;
import net.luminis.tls.util.FieldSetter;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldReader;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.luminis.tls.TlsConstants.CipherSuite.*;
import static net.luminis.tls.TlsConstants.SignatureScheme.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class TlsClientEngineTest extends EngineTest {

    private TlsClientEngine engine;
    private ECPublicKey publicKey;
    private ClientMessageSender messageSender;


    @BeforeEach
    void initObjectUnderTest() {
        messageSender = Mockito.mock(ClientMessageSender.class);
        engine = new TlsClientEngine(messageSender, Mockito.mock(TlsStatusEventHandler.class));
        engine.setServerName("server");
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));

        publicKey = KeyUtils.generatePublicKey();
    }

    @Test
    void serverHelloShouldContainMandatoryExtensions() {
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256);

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloShouldContainSupportedVersionExtension() {
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloSupportedVersionExtensionShouldContainRightVersion() throws Exception {
        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello);
        FieldSetter.setField(supportedVersionsExtension, supportedVersionsExtension.getClass().getDeclaredField("tlsVersion"), (short) 0x0303);
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension(), supportedVersionsExtension));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloShouldContainPreSharedKeyOrKeyShareExtension() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(TlsProtocolException.class);
    }

    @Test
    void serverHelloShouldNotContainOtherExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello),
                new ServerNameExtension("server")));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void engineAcceptsCorrectServerHello() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();

        engine.received(serverHello, ProtectionKeysType.None);
    }

    @Test
    void serverHelloShouldContainCipherThatClientOffered() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_256_GCM_SHA384, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello, ProtectionKeysType.None)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void afterProperServerHelloSelectedCipherIsAvailable() throws Exception {
        // Given
        engine.startHandshake();
        Assertions.assertThatThrownBy(() ->
                engine.getSelectedCipher()
        ).isInstanceOf(IllegalStateException.class);

        // When
        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // Then
        Assertions.assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
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
        engine.received(serverHello2, ProtectionKeysType.None);

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void encryptedExtensionsShouldNotBeReceivedBeforeServerHello() throws Exception {
        // Given
        engine.startHandshake();

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(Collections.emptyList()), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainExtensionNotOfferedByClient() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();

        engine.received(serverHello, ProtectionKeysType.None);

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(List.of(new DummyExtension())), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainDuplicateTypes() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();

        engine.received(serverHello, ProtectionKeysType.None);

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(List.of(
                        new ServerNameExtension("server"),
                        new ServerNameExtension("server")
                )), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void certificateMessageShouldNotBeReceivedBeforeEncryptedExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // When, no Encrypted Extensions Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateMessage(), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void serverCertificateMessageRequestContextShouldBeEmpty() throws Exception {
        handshakeUpToCertificate();

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getEncoded()).thenReturn(new byte[300]);
        CertificateMessage certificateMessage = new CertificateMessage(new byte[4], cert);

        Assertions.assertThatThrownBy(() ->
                engine.received(certificateMessage, ProtectionKeysType.Handshake)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverCertificateMessageShouldAlwaysContainAtLeastOneCertificate() throws Exception {
        handshakeUpToCertificate();

        CertificateMessage certificateMessage = new CertificateMessage();
        byte[] emptyCertificateMessageData = ByteUtils.hexToBytes("0b000009" + "00" + "000005" + "0000000000");
        certificateMessage.parse(ByteBuffer.wrap(emptyCertificateMessageData));

        Assertions.assertThatThrownBy(() ->
                engine.received(certificateMessage, ProtectionKeysType.Handshake)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void certificateVerifyShouldNotBeReceivedBeforeCertificateMessage() throws Exception {
        // Given
        handshakeUpToCertificate();

        // When, no Certificate Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage(), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void certificateVerifySignatureSchemeShouldMatch() throws Exception {
        // Given
        handshakeUpToCertificate(List.of(TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256));
        Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);
        engine.received(new CertificateMessage((X509Certificate) certificate), ProtectionKeysType.Handshake);

        Assertions.assertThatThrownBy(() ->
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

        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        // When
        engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake);
        // Then
        // Ok
    }

    @Test
    void whenSignatureVerificationFailsHandshakeShouldBeTerminatedWithDecryptError() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, new byte[256]), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void testVerifySignature() throws Exception {
        byte[] signature = createServerSignature();

        Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);

        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0x01);

        boolean verified = engine.verifySignature(signature, rsa_pss_rsae_sha256, certificate, hash);

        Assertions.assertThat(verified).isTrue();
    }

    @Test
    void unknownCertificateShouldAbortTls() throws Exception {
        // Given
        byte[] validSignature = createServerSignature();
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(BadCertificateAlert.class);
    }

    @Test
    void certificateWithoutMatchingServerNameShouldAbortTls() throws Exception {
        // Given
        engine.setHostnameVerifier(createAlwaysRefusingVerifier());
        engine.setTrustManager(createNoOpTrustManager());

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        byte[] validSignature = createServerSignature();
        Assertions.assertThatThrownBy(() ->
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
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        // When
        engine.setHostnameVerifier(null);
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake))
                // Then
                .isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void finisedMessageShouldNotBeReceivedBeforeCertificateVerify() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        // When, no Certificate Verify Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void withPskAcceptedFinisedMessageShouldFollowEncryptedExentions() throws Exception {
        // Given
        handshakeUpToCertificate();
        FieldSetter.setField(engine, engine.getClass().getDeclaredField("pskAccepted"), true);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake))
                // Then
        .isInstanceOf(DecryptErrorAlert.class);  // And not UnexpectedMessageAlert
    }

    @Test
    void withPskAcceptedFinisedMessageShouldNotBeReceivedBeforeEncryptedExentions() throws Exception {
        // Given
        handshakeUpToEncryptedExtensions();
        FieldSetter.setField(engine, engine.getClass().getDeclaredField("pskAccepted"), true);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[256]), ProtectionKeysType.Handshake))
                // Then
        .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void incorrectServerFinishedShouldAbortTls() throws Exception {
        handshakeUpToFinished();

        FinishedMessage finishedMessage = new FinishedMessage(new byte[256]);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(finishedMessage, ProtectionKeysType.Handshake))
                // Then
        .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void engineShouldSendClientFinishedWhenHandshakeDone() throws Exception {
        handshakeUpToFinished();

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngine stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }

    @Test
    void certificateRequestMessageShouldNotBeReceivedBeforeEncryptedExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);

        // Then
        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension()), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void certificateRequestMessageShouldNotBeReceivedAfterCertificate() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)), ProtectionKeysType.Handshake);

        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension()), ProtectionKeysType.Handshake)
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void withoutClientCertificateClientAuthLeadsToAdditionalCertificateMessageBeforeFinished() throws Exception {
        // Given
        handshakeUpToFinished(List.of(rsa_pss_rsae_sha256), true, null);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngine stubbedEngine = Mockito.spy(engine);
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
        TlsClientEngine stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        // When
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        // Then
        Mockito.verify(messageSender).send(ArgumentMatchers.any(CertificateMessage.class));
        Mockito.verify(messageSender).send(ArgumentMatchers.any(CertificateVerifyMessage.class));
        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }

    @Test
    void unsupportedSignatureSchemeLeadsToException() throws Exception {
        assertThatThrownBy(() ->
                // When
                engine.startHandshake(TlsConstants.NamedGroup.secp256r1,
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
        TlsClientEngine stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        // When
        stubbedEngine.received(finishedMessage, ProtectionKeysType.Handshake);

        // Then
        ArgumentCaptor<CertificateVerifyMessage> messageCaptor = ArgumentCaptor.forClass(CertificateVerifyMessage.class);
        verify(messageSender).send(messageCaptor.capture());
        assertThat(messageCaptor.getValue().getSignatureScheme()).isEqualTo(rsa_pss_rsae_sha384);
    }

    private ServerHello createDefaultServerHello() {
        return createDefaultServerHello(TLS_AES_128_GCM_SHA256);
    }

    private ServerHello createDefaultServerHello(TlsConstants.CipherSuite cipherSuite) {
        return new ServerHello(cipherSuite, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
    }

    private void handshakeUpToEncryptedExtensions() throws Exception {
        handshakeUpToEncryptedExtensions(List.of(rsa_pss_rsae_sha256));
    }

    private void handshakeUpToEncryptedExtensions(List<TlsConstants.SignatureScheme> signatureSchemes) throws Exception {
        engine.startHandshake(TlsConstants.NamedGroup.secp256r1, signatureSchemes);

        ServerHello serverHello = createDefaultServerHello();
        engine.received(serverHello, ProtectionKeysType.None);
        Mockito.clearInvocations(messageSender);
    }

    private void handshakeUpToCertificate() throws Exception {
        handshakeUpToCertificate(List.of(rsa_pss_rsae_sha256));
    }

    private void handshakeUpToCertificate(List<TlsConstants.SignatureScheme> signatureSchemes) throws Exception {
        handshakeUpToEncryptedExtensions(signatureSchemes);

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
        handshakeUpToCertificate(signatureSchemes);
        if (requestClientCert) {
            if (clientAuthRequiredSignatureScheme == null) {
                clientAuthRequiredSignatureScheme = rsa_pss_rsae_sha256;
            }
            engine.received(new CertificateRequestMessage(new SignatureAlgorithmsExtension(clientAuthRequiredSignatureScheme)), ProtectionKeysType.Handshake);
        }
        X509Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);
        byte[] validSignature = createServerSignature();
        engine.setTrustManager(createNoOpTrustManager());
        engine.setHostnameVerifier(createNoOpHostnameVerifier());
        engine.received(new CertificateMessage(certificate), ProtectionKeysType.Handshake);
        engine.received(new CertificateVerifyMessage(rsa_pss_rsae_sha256, validSignature), ProtectionKeysType.Handshake);
    }

    private byte[] createServerSignature() throws Exception {
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
        public byte[] getBytes() {
            return new byte[0];
        }
    }
}