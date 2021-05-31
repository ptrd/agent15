/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;

import javax.net.ssl.X509TrustManager;
import java.nio.ByteBuffer;
import java.security.*;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TlsClientEngineTest extends EngineTest {

    private TlsClientEngine engine;
    private ECPublicKey publicKey;
    private ClientMessageSender messageSender;


    @BeforeEach
    private void initObjectUnderTest() {
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
                engine.received(serverHello)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloShouldContainSupportedVersionExtension() {
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloSupportedVersionExtensionShouldContainRightVersion() throws Exception {
        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello);
        FieldSetter.setField(supportedVersionsExtension, supportedVersionsExtension.getClass().getDeclaredField("tlsVersion"), (short) 0x0303);
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension(), supportedVersionsExtension));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloShouldContainPreSharedKeyOrKeyShareExtension() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello)
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
                engine.received(serverHello)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void engineAcceptsCorrectServerHello() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));

        engine.received(serverHello);
    }

    @Test
    void serverHelloShouldContainCipherThatClientOffered() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_256_GCM_SHA384, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new ServerPreSharedKeyExtension()));

        Assertions.assertThatThrownBy(() ->
                engine.received(serverHello)
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
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);

        // Then
        Assertions.assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void afterProperServerHelloTrafficSecretsAreAvailable() throws Exception {
        // Given
        engine.startHandshake();
        Assertions.assertThat(engine.getClientHandshakeTrafficSecret()).isNull();

        // When
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);

        // Then
        Assertions.assertThat(engine.getClientHandshakeTrafficSecret())
                .isNotNull()
                .hasSizeGreaterThan(12);
    }

    @Test
    void encryptedExtensionsShouldNotBeReceivedBeforeServerHello() throws Exception {
        // Given
        engine.startHandshake();

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(Collections.emptyList()))
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainExtensionNotOfferedByClient() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));

        engine.received(serverHello);

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(List.of(new DummyExtension())))
        ).isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void encryptedExtensionsShouldNotContainDuplicateTypes() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));

        engine.received(serverHello);

        Assertions.assertThatThrownBy(() ->
                engine.received(new EncryptedExtensions(List.of(
                        new ServerNameExtension("server"),
                        new ServerNameExtension("server")
                )))
        ).isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void certificateMessageShouldNotBeReceivedBeforeEncryptedExtensions() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);

        // When, no Encrypted Extensions Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateMessage())
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void serverCertificateMessageRequestContextShouldBeEmpty() throws Exception {
        handshakeUpToCertificate();

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getEncoded()).thenReturn(new byte[300]);
        CertificateMessage certificateMessage = new CertificateMessage(new byte[4], cert);

        Assertions.assertThatThrownBy(() ->
                engine.received(certificateMessage)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverCertificateMessageShouldAlwaysContainAtLeastOneCertificate() throws Exception {
        handshakeUpToCertificate();

        CertificateMessage certificateMessage = new CertificateMessage();
        byte[] emptyCertificateMessageData = ByteUtils.hexToBytes("0b000009" + "00" + "000005" + "0000000000");
        certificateMessage.parse(ByteBuffer.wrap(emptyCertificateMessageData));

        Assertions.assertThatThrownBy(() ->
                engine.received(certificateMessage)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void certificateVerifyShouldNotBeReceivedBeforeCertificateMessage() throws Exception {
        // Given
        handshakeUpToCertificate();

        // When, no Certificate Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage())
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void certificateVerifySignatureSchemeShouldMatch() throws Exception {
        // Given
        handshakeUpToCertificate(List.of(TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256));
        Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);
        engine.received(new CertificateMessage((X509Certificate) certificate));

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, new byte[0])))
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

        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        // When
        engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, validSignature));
        // Then
        // Ok
    }

    @Test
    void whenSignatureVerificationFailsHandshakeShouldBeTerminatedWithDecryptError() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, new byte[256])))
                // Then
                .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void testVerifySignature() throws Exception {
        byte[] signature = createServerSignature();

        Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);

        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0x01);

        boolean verified = engine.verifySignature(signature, TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, certificate, hash);

        Assertions.assertThat(verified).isTrue();
    }

    @Test
    void unknownCertificateShouldAbortTls() throws Exception {
        // Given
        byte[] validSignature = createServerSignature();
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, validSignature)))
                // Then
                .isInstanceOf(BadCertificateAlert.class);
    }

    @Test
    void certificateWithoutMatchingServerNameShouldAbortTls() throws Exception {
        // Given
        engine.setHostnameVerifier(createAlwaysRefusingVerifier());
        engine.setTrustManager(createNoOpTrustManager());

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        byte[] validSignature = createServerSignature();
        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, validSignature)))
                // Then
                .isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void clearingHostnameVerifierDoesNotBypassDefaultVerification() throws Exception {
        // Given
        engine.setTrustManager(createNoOpTrustManager());
        byte[] validSignature = createServerSignature();

        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        // When
        engine.setHostnameVerifier(null);
        Assertions.assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, validSignature)))
                // Then
                .isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void finisedMessageShouldNotBeReceivedBeforeCertificateVerify() throws Exception {
        // Given
        handshakeUpToCertificate();
        engine.received(new CertificateMessage(CertificateUtils.inflateCertificate(encodedCertificate)));

        // When, no Certificate Verify Message received
        // Then
        Assertions.assertThatThrownBy(() ->
                engine.received(new FinishedMessage(new byte[256]))
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void withPskAcceptedFinisedMessageShouldFollowEncryptedExentions() throws Exception {
        // Given
        handshakeUpToCertificate();
        FieldSetter.setField(engine, engine.getClass().getDeclaredField("pskAccepted"), true);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[256])))
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
                engine.received(new FinishedMessage(new byte[256])))
                // Then
        .isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void incorrectServerFinishedShouldAbortTls() throws Exception {
        handshakeUpToFinished();
        Mockito.when(engine.getState().getServerHandshakeTrafficSecret()).thenReturn(new byte[32]);
        Mockito.when(engine.getState().getHashLength()).thenReturn((short) 32);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[256]);

        Assertions.assertThatThrownBy(() ->
                // When
                engine.received(finishedMessage))
                // Then
        .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void engineShouldSendClientFinishedWhenHandshakeDone() throws Exception {
        handshakeUpToFinished();

        Mockito.when(engine.getState().getServerHandshakeTrafficSecret()).thenReturn(new byte[32]);
        Mockito.when(engine.getState().getHashLength()).thenReturn((short) 32);

        FinishedMessage finishedMessage = new FinishedMessage(new byte[32]);
        TlsClientEngine stubbedEngine = Mockito.spy(engine);
        Mockito.doReturn(new byte[32]).when(stubbedEngine).computeFinishedVerifyData(ArgumentMatchers.any(), ArgumentMatchers.any());
        stubbedEngine.received(finishedMessage);

        Mockito.verify(messageSender).send(ArgumentMatchers.any(FinishedMessage.class));
    }


    private void handshakeUpToEncryptedExtensions() throws Exception {
        handshakeUpToEncryptedExtensions(List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256));
    }

    private void handshakeUpToEncryptedExtensions(List<TlsConstants.SignatureScheme> signatureSchemes) throws Exception {
        engine.startHandshake(TlsConstants.NamedGroup.secp256r1, signatureSchemes);

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);
        Mockito.clearInvocations(messageSender);
    }

    private void handshakeUpToCertificate() throws Exception {
        handshakeUpToCertificate(List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256));
    }

    private void handshakeUpToCertificate(List<TlsConstants.SignatureScheme> signatureSchemes) throws Exception {
        handshakeUpToEncryptedExtensions(signatureSchemes);

        TranscriptHash transcriptHash = (TranscriptHash) Mockito.spy(new FieldReader(engine, engine.getClass().getDeclaredField("transcriptHash")).read());
        Mockito.doReturn(ByteUtils.hexToBytes("0101010101010101010101010101010101010101010101010101010101010101")).when(transcriptHash).getHash(ArgumentMatchers.argThat(t -> t == TlsConstants.HandshakeType.certificate));
        FieldSetter.setField(engine, engine.getClass().getDeclaredField("transcriptHash"), transcriptHash);

        engine.received(new EncryptedExtensions());
    }

    private void handshakeUpToFinished() throws Exception {
        handshakeUpToCertificate(List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256));
        TlsState state = Mockito.spy(engine.getState());
        FieldSetter.setField(engine, engine.getClass().getSuperclass().getDeclaredField("state"), state);
        X509Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);
        byte[] validSignature = createServerSignature();
        engine.setTrustManager(createNoOpTrustManager());
        engine.setHostnameVerifier(createNoOpHostnameVerifier());
        engine.received(new CertificateMessage(certificate));
        engine.received(new CertificateVerifyMessage(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, validSignature));
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



    public static class CertificateMessageTest {

        @Test
        void parseCertificateMessage() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes(gmailCertificateMessageBytes);
            CertificateMessage cm = new CertificateMessage();
            cm.parse(ByteBuffer.wrap(rawData));
            assertThat(cm.getEndEntityCertificate()).isNotNull();
            assertThat(cm.getCertificateChain()).hasSizeGreaterThan(1);

            // Verify that certificate can be generated.
            List<Object> names = cm.getEndEntityCertificate().getSubjectAlternativeNames().stream()
                    .flatMap(l -> Stream.of(l.get(1)))
                    .collect(Collectors.toList());
            assertThat(names).contains("gmail.com");
        }

        @Test
        void parseNoMessage() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b00");
            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void parseNotEnoughBytesForMessage() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b000066");
            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void parseSingleCertificateMessage() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                    // cert list size cert data size
                    + "0004d6" +      "0004d1" + gmailCertificateBytes + "0000");
            CertificateMessage cm = new CertificateMessage().parse(ByteBuffer.wrap(rawData));
            assertThat(cm.getCertificateChain()).hasSize(1);
        }

        @Test
        void parseInvalidCertificate() throws Exception {
            byte[] bogusCert = new byte[1233];
            byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                    // cert list size cert data size
                    + "0004d6" +      "0004d1" + ByteUtils.bytesToHex(bogusCert) + "0000");

            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(BadCertificateAlert.class);
        }

        @Test
        void parseMessageWithoutCertificate() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b000009" + "00" + "000005" + "000000" + "0000");

            CertificateMessage cm = new CertificateMessage().parse(ByteBuffer.wrap(rawData));

            assertThat(cm.getCertificateChain()).hasSize(0);
        }

        @Test
        void parseCertificateMessageWithIncorrectCertificateRequestContextLength() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "ff"
                    // cert list size cert data size
                    + "0004d6" +      "000020" + "012345678901234567890123456789012345678901" + "0000");

            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void parseCertificateMessageWithIncorrectCertificateListLength() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "00"
                    // cert list size cert data size
                    + "0004d6" +      "000020" + "012345678901234567890123456789012345678901" + "0000");

            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void parseCertificateMessageWithIncorrectCertificateLength() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "00"
                    // cert list size cert data size
                    + "000024" +      "000020" + "0123456789012345678901234567890123456789" + "0000");

            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void parseCertificateMessageWithIncorrectCertificateExtensionLength() throws Exception {
            byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                    // cert list size cert data size
                    + "0004d6" +      "0004d1" + gmailCertificateBytes + "00ff");

            assertThatThrownBy(() ->
                    new CertificateMessage().parse(ByteBuffer.wrap(rawData))
            ).isInstanceOf(DecodeErrorException.class);
        }

        @Test
        void serializeCertificateMessage() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            when(cert.getEncoded()).thenReturn(new byte[300]);
            CertificateMessage certificateMessage = new CertificateMessage(cert);

            byte[] data = certificateMessage.getBytes();
            int messageLength = 4 + ByteBuffer.wrap(data).getInt() & 0x00ffffff;
            assertThat(data.length).isEqualTo(messageLength);
        }


        String gmailCertificateMessageBytes = "0b00092d000009290004d1308204cd308203b5a003020102021100a07defd2e6ff026c08"
                + "000000003ebf0d300d06092a864886f70d01010b05003042310b3009060355040613025553311e301c060355040a1315476f6f67"
                + "6c65205472757374205365727669636573311330110603550403130a47545320434120314f31301e170d32303035303530383336"
                + "31305a170d3230303732383038333631305a3063310b3009060355040613025553311330110603550408130a43616c69666f726e"
                + "6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433112301006"
                + "035504031309676d61696c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e47e42dfb934737833dd"
                + "b6e4507c2a7775f3f759b88dec3478e7dce3cc04ae42ab381472c7a7c27069b694299a905c33a6107ae7347ae43a34ae70f42eac"
                + "fbc0a382026630820262300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c060355"
                + "1d130101ff04023000301d0603551d0e04160414a841046aa9ccef3104c311cc69a9e7cdd40dc93d301f0603551d230418301680"
                + "1498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b306806082b06010505070101045c305a302b06082b06010505073001861f68"
                + "7474703a2f2f6f6373702e706b692e676f6f672f677473316f31636f7265302b06082b06010505073002861f687474703a2f2f70"
                + "6b692e676f6f672f677372322f475453314f312e63727430210603551d11041a30188209676d61696c2e636f6d820b2a2e676d61"
                + "696c2e636f6d30210603551d20041a30183008060667810c010202300c060a2b06010401d67902050330330603551d1f042c302a"
                + "3028a026a0248622687474703a2f2f63726c2e706b692e676f6f672f475453314f31636f72652e63726c30820106060a2b060104"
                + "01d6790204020481f70481f400f2007700b21e05cc8ba2cd8a204e8766f92bb98a2520676bdafa70e7b249532def8b905e000001"
                + "71e43155ad0000040300483046022100d6815e996faf6cde205f674ef2356b0350291e0e68ed5aaa9cb3282ac5fd825e022100b7"
                + "c39d624386e538f2dc3bdb31e0d1206d4a1fb3d0a660bfbc3b17680f5633320077005ea773f9df56c0e7b536487dd049e0327a91"
                + "9a0c84a11212841875968171455800000171e43155ae0000040300483046022100c72bde3052e0a20a2c88df3cbd4f83e94513dd"
                + "a41f924b324e13e105360c5b57022100c2cdf5111cda53c29080f39f73450dce6284d0f2c46dde483d589be62ac3565a300d0609"
                + "2a864886f70d01010b050003820101002f475e22cb4ea5b4c049abf0593a6be7cefc91901bb8cce91bb2abfe651427324472fb66"
                + "39f46e7b20cfb6626a9605fd2d56d1aa1b058b752dfcad326a219f30001f72b43ed6d0c3e162b7cd7bf82eb92ed7e79e2fc51e61"
                + "0953907549a6361dd1f9a6e01da1a6ec4ad786fc469b1c0fccfc695a4ff6566597a3ade8fe051df463e7a6fd5a14021caeb218ff"
                + "4b2bfe049bf30ab69d432ee85a15bcba47f2d584e9c22665ad24bcf487aff3f6328bd60bcac5354c5306d6b299d98cc1bf52de4b"
                + "5b079df2578f512476ca58bb8067287baff654ca1a1e161703befbf50be5a2911551c86483bd893fb9f630e8fc3339e105d06689"
                + "aa670e484d076c322eb1eda9000000044e3082044a30820332a003020102020d01e3b49aa18d8aa981256950b8300d06092a8648"
                + "86f70d01010b0500304c3120301e060355040b1317476c6f62616c5369676e20526f6f74204341202d2052323113301106035504"
                + "0a130a476c6f62616c5369676e311330110603550403130a476c6f62616c5369676e301e170d3137303631353030303034325a17"
                + "0d3231313231353030303034325a3042310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374"
                + "205365727669636573311330110603550403130a47545320434120314f3130820122300d06092a864886f70d0101010500038201"
                + "0f003082010a0282010100d018cf45d48bcdd39ce440ef7eb4dd69211bc9cf3c8e4c75b90f3119843d9e3c29ef500d10936f0580"
                + "809f2aa0bd124b02e13d9f581624fe309f0b747755931d4bf74de1928210f651ac0cc3b222940f346b981049e70b9d8339dd20c6"
                + "1c2defd1186165e7238320a82312ffd2247fd42fe7446a5b4dd75066b0af9e426305fbe01cc46361af9f6a33ff6297bd48d9d37c"
                + "1467dc75dc2e69e8f86d7869d0b71005b8f131c23b24fd1a3374f823e0ec6b198a16c6e3cda4cd0bdbb3a4596038883bad1db9c6"
                + "8ca7531bfcbcd9a4abbcdd3c61d7931598ee81bd8fe264472040064ed7ac97e8b9c05912a1492523e4ed70342ca5b4637cf9a33d"
                + "83d1cd6d24ac070203010001a38201333082012f300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601"
                + "050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e0416041498d1f86e10eb"
                + "cf9bec609f18901ba0eb7d09fd2b301f0603551d230418301680149be20757671c1ec06a06de59b49a2ddfdc19862e303506082b"
                + "0601050507010104293027302506082b060105050730018619687474703a2f2f6f6373702e706b692e676f6f672f677372323032"
                + "0603551d1f042b30293027a025a0238621687474703a2f2f63726c2e706b692e676f6f672f677372322f677372322e63726c303f"
                + "0603551d20043830363034060667810c010202302a302806082b06010505070201161c68747470733a2f2f706b692e676f6f672f"
                + "7265706f7369746f72792f300d06092a864886f70d01010b050003820101001a803e3679fbf32ea946377d5e541635aec74e0899"
                + "febdd13469265266073d0aba49cb62f4f11a8efc114f68964c742bd367deb2a3aa058d844d4c20650fa596da0d16f86c3bdb6f04"
                + "23886b3a6cc160bd689f718eee2d583407f0d554e98659fd7b5e0d2194f58cc9a8f8d8f2adcc0f1af39aa7a90427f9a3c9b0ff02"
                + "786b61bac7352be856fa4fc31c0cedb63cb44beaedcce13cecdc0d8cd63e9bca42588bcc16211740bca2d666efdac4155bcd89aa"
                + "9b0926e732d20d6e6720025b10b090099c0c1f9eadd83beaa1fc6ce8105c085219512a71bbac7ab5dd15ed2bc9082a2c8ab4a621"
                + "ab63ffd7524950d089b7adf2affb50ae2fe1950df346ad9d9cf5ca0000";

        String gmailCertificateBytes = "308204cd308203b5a003020102021100a07defd2e6ff026c08"
                + "000000003ebf0d300d06092a864886f70d01010b05003042310b3009060355040613025553311e301c060355040a1315476f6f67"
                + "6c65205472757374205365727669636573311330110603550403130a47545320434120314f31301e170d32303035303530383336"
                + "31305a170d3230303732383038333631305a3063310b3009060355040613025553311330110603550408130a43616c69666f726e"
                + "6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433112301006"
                + "035504031309676d61696c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e47e42dfb934737833dd"
                + "b6e4507c2a7775f3f759b88dec3478e7dce3cc04ae42ab381472c7a7c27069b694299a905c33a6107ae7347ae43a34ae70f42eac"
                + "fbc0a382026630820262300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c060355"
                + "1d130101ff04023000301d0603551d0e04160414a841046aa9ccef3104c311cc69a9e7cdd40dc93d301f0603551d230418301680"
                + "1498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b306806082b06010505070101045c305a302b06082b06010505073001861f68"
                + "7474703a2f2f6f6373702e706b692e676f6f672f677473316f31636f7265302b06082b06010505073002861f687474703a2f2f70"
                + "6b692e676f6f672f677372322f475453314f312e63727430210603551d11041a30188209676d61696c2e636f6d820b2a2e676d61"
                + "696c2e636f6d30210603551d20041a30183008060667810c010202300c060a2b06010401d67902050330330603551d1f042c302a"
                + "3028a026a0248622687474703a2f2f63726c2e706b692e676f6f672f475453314f31636f72652e63726c30820106060a2b060104"
                + "01d6790204020481f70481f400f2007700b21e05cc8ba2cd8a204e8766f92bb98a2520676bdafa70e7b249532def8b905e000001"
                + "71e43155ad0000040300483046022100d6815e996faf6cde205f674ef2356b0350291e0e68ed5aaa9cb3282ac5fd825e022100b7"
                + "c39d624386e538f2dc3bdb31e0d1206d4a1fb3d0a660bfbc3b17680f5633320077005ea773f9df56c0e7b536487dd049e0327a91"
                + "9a0c84a11212841875968171455800000171e43155ae0000040300483046022100c72bde3052e0a20a2c88df3cbd4f83e94513dd"
                + "a41f924b324e13e105360c5b57022100c2cdf5111cda53c29080f39f73450dce6284d0f2c46dde483d589be62ac3565a300d0609"
                + "2a864886f70d01010b050003820101002f475e22cb4ea5b4c049abf0593a6be7cefc91901bb8cce91bb2abfe651427324472fb66"
                + "39f46e7b20cfb6626a9605fd2d56d1aa1b058b752dfcad326a219f30001f72b43ed6d0c3e162b7cd7bf82eb92ed7e79e2fc51e61"
                + "0953907549a6361dd1f9a6e01da1a6ec4ad786fc469b1c0fccfc695a4ff6566597a3ade8fe051df463e7a6fd5a14021caeb218ff"
                + "4b2bfe049bf30ab69d432ee85a15bcba47f2d584e9c22665ad24bcf487aff3f6328bd60bcac5354c5306d6b299d98cc1bf52de4b"
                + "5b079df2578f512476ca58bb8067287baff654ca1a1e161703befbf50be5a2911551c86483bd893fb9f630e8fc3339e105d06689"
                + "aa670e484d076c322eb1eda9";

    }
}