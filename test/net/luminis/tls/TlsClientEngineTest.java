package net.luminis.tls;

import net.luminis.tls.exception.MissingExtensionAlert;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.ServerNameExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static net.luminis.tls.TlsConstants.CipherSuite.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class TlsClientEngineTest {

    private TlsClientEngine engine;
    private ECPublicKey publicKey;


    @BeforeEach
    private void initObjectUnderTest() {
        engine = new TlsClientEngine(mock(ClientMessageSender.class));
        engine.setServerName("server");
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));

        publicKey = (ECPublicKey) generateKeys()[1];
    }

    @Test
    void serverHelloShouldContainMandatoryExtensions() {
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256);

        assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloShouldContainSupportedVersionExtension() {
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void serverHelloSupportedVersionExtensionShouldContainRightVersion() throws Exception {
        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello);
        FieldSetter.setField(supportedVersionsExtension, supportedVersionsExtension.getClass().getDeclaredField("tlsVersion"), (short) 0x0303);
        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension(), supportedVersionsExtension));

        assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverHelloShouldContainPreSharedKeyOrKeyShareExtension() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_CCM_8_SHA256, List.of(new ServerPreSharedKeyExtension()));

        assertThatThrownBy(() ->
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

        assertThatThrownBy(() ->
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

        assertThatThrownBy(() ->
                engine.received(serverHello)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void afterProperServerHelloSelectedCipherIsAvailable() throws Exception {
        // Given
        engine.startHandshake();
        assertThatThrownBy(() ->
                engine.getSelectedCipher()
        ).isInstanceOf(IllegalStateException.class);

        // When
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void afterProperServerHelloTrafficSecretsAreAvailable() throws Exception {
        // Given
        engine.startHandshake();
        assertThatThrownBy(() ->
                engine.getClientHandshakeTrafficSecret()
        ).isInstanceOf(IllegalStateException.class);

        // When
        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);

        // Then
        assertThat(engine.getClientHandshakeTrafficSecret())
                .isNotNull()
                .hasSizeGreaterThan(12);
    }

    @Test
    void encryptedExtensionsShouldNotBeReceivedBeforeServerHello() throws Exception {
        // Given
        engine.startHandshake();

        assertThatThrownBy(() ->
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

        assertThatThrownBy(() ->
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

        assertThatThrownBy(() ->
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
        assertThatThrownBy(() ->
                engine.received(new CertificateMessage())
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void serverCertificateMessageRequestContextShouldBeEmpty() throws Exception {
        handshakeUpToCertificate();

        CertificateMessage certificateMessage = new CertificateMessage(new byte[4], mock(X509Certificate.class));

        assertThatThrownBy(() ->
                engine.received(certificateMessage)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serverCertificateMessageShouldAlwaysContainAtLeastOneCertificate() throws Exception {
        handshakeUpToCertificate();

        CertificateMessage certificateMessage = new CertificateMessage(null);

        assertThatThrownBy(() ->
                engine.received(certificateMessage)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void certificateVerifyShouldNotBeReceivedBeforeCertificateMessage() throws Exception {
        // Given
        handshakeUpToCertificate();

        // When, no Certificate Message received
        // Then
        assertThatThrownBy(() ->
                engine.received(new CertificateVerifyMessage())
        ).isInstanceOf(UnexpectedMessageAlert.class);
    }

    @Test
    void testVerifySignature() throws Exception {
        byte[] signature = createServerSignature();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.getBytes())));

        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0x01);

        boolean verified = engine.verifySignature(signature, TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, certificate, hash);

        assertThat(verified).isTrue();
    }


    private void handshakeUpToCertificate() throws Exception {
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello)));
        engine.received(serverHello);
        engine.received(new EncryptedExtensions());
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


    ECKey[] generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            return new ECKey[] { (ECPrivateKey) keyPair.getPrivate(), (ECPublicKey) keyPair.getPublic() };
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    static class DummyExtension extends Extension {

        @Override
        public byte[] getBytes() {
            return new byte[0];
        }
    }

    private String encodedCertificate = "MIICxzCCAa+gAwIBAgIEJ4Jd0zANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlr" +
            "d2lrLnRlY2gwHhcNMjAwNjAxMTAyNDMzWhcNMjEwNjAxMTAyNDMzWjAUMRIwEAYD" +
            "VQQDEwlrd2lrLnRlY2gwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCD" +
            "fGLG29p6hjY251wLhSWd1Al9utOd3pkUteFX4pXDi8pgumq3pL6CsEsD9sj1XmCX" +
            "CcWWTVlU0tPHq74daA/gm6KHubtNmyLESS38e5gjC3PCRz5ock4h9IZvsrhoFz9K" +
            "pFs3edTtglaiB0dl2nIm281upk3f2qXN/+JQAK9F5jtimYRaNfUGkPFyHy278tzu" +
            "xEblg+TreCA8L7TJjJz/H/Y+OtYgZFza6K6mGxhm6ykHKbNZOfv76k0KJTC4u/Fz" +
            "V2ReFqfwYip+S4/8M9QHbIx1xQwbFBeDhTQHfM6jak1GrzbIGTs6TWpFFzv7qQip" +
            "DP29HpI5Xgsjy8J5ui9fAgMBAAGjITAfMB0GA1UdDgQWBBQKETVqXNREe51yGXst" +
            "Z+TQkh21bDANBgkqhkiG9w0BAQsFAAOCAQEAWuVsyQLbUdasz1YgbYzdH8SsxtVe" +
            "EwJIhw3YQk9ongDaFxogk+rgqMTBt8CBU0OzYqddKPSCtm1RQGG08qQv00Rzev3c" +
            "VsDHZZM9GiK1TYHnYeYc2hV9UCxxmEcDrs86NHV+eCGjTuw8FJr3owLJs/lnukbw" +
            "SFHMKmPIHbNn1LLMR0oEu7w0h8DEQ6CI/lfpF/F+mcgjrHrDgvC0QP+0ZiUH95YL" +
            "OBaxTtxi3ZDIfGofw3tHJoq55I4SuZcvCKid0FKeCunomfuIHsvCVyVYJcHSaMMa" +
            "vMBM0Kn6CfdkQukplJzwNujbXJtvxx4a7+UPEzfEmBUuuVRZ3rzjq2u46w==";

    private String encodedPrivateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCDfGLG29p6hjY2" +
            "51wLhSWd1Al9utOd3pkUteFX4pXDi8pgumq3pL6CsEsD9sj1XmCXCcWWTVlU0tPH" +
            "q74daA/gm6KHubtNmyLESS38e5gjC3PCRz5ock4h9IZvsrhoFz9KpFs3edTtglai" +
            "B0dl2nIm281upk3f2qXN/+JQAK9F5jtimYRaNfUGkPFyHy278tzuxEblg+TreCA8" +
            "L7TJjJz/H/Y+OtYgZFza6K6mGxhm6ykHKbNZOfv76k0KJTC4u/FzV2ReFqfwYip+" +
            "S4/8M9QHbIx1xQwbFBeDhTQHfM6jak1GrzbIGTs6TWpFFzv7qQipDP29HpI5Xgsj" +
            "y8J5ui9fAgMBAAECggEAWddn9tDKW+XQrXswXX7A0TLMuWgqqDgtCQWtz8s24cJm" +
            "qek2efzLX6jt2OuLLH0sKoe2xphbbaYQpuImqRktoB830t2JqeFSxCPslBQvQ+LT" +
            "WfAsKFnSIUlfgnrvndAkou/ik+lfIFpqr5OhqWq1jO+rUuu3UjmoCTXKgTe2i19k" +
            "/MeoNP6/OvzuHy8mQLb2Zf2nBx6h+Xn29vvsjvyIhBzSvtZCq9pcPdmRku8CPfql" +
            "cWjGvAGEKxzsSJS5jE4doet+8h+kjgeWUE6jP2Nbkj4yr7pRbKd2PhGlZ0kdfpWz" +
            "1HipRpJ3lilI2ddknU9c6wxl0cKNtM6+/vBT3/V2AQKBgQDM2s5rmqZwmoFIhJ6M" +
            "TFVXGOY5iW/Wj3vhGAQxG4ZPdIOIfH+yvQmSEBjGqkN4BJFlh3EHj8cHFbSggOAf" +
            "0obrMwbXCnzVH4zP0gwyr9xiZlNqA4EmwmvFm22R1X5JjBmq/Nn9HjXLs+/Hy+Uz" +
            "EdoATv44RlclilrOCNCnzF0zHwKBgQCkUD6vfHNvVBhjjCv3q2gQYhzRNtFkOcDV" +
            "scs4+nbEcq8kCMwHUVomvZt5gjr6edSQjNWkpdfYrWai7F8CHv0aSGc7RO2YGw9d" +
            "3/fQpwTC77qYegLyLkd7p1UmVyOm6eHT68bU6hn2QXYhmRgQ+0GzHIOeWTWaPTMC" +
            "fJr/4AG7wQKBgByHcG3t6LYP3mdiCM6TJuNtVUq4CDpCW0c62AKaybaxDExqwkH7" +
            "L6UG1tx8A89oG3OfTC94Z4hmDnS33f6wjBefUJmMHVx0+2BJ6Wb5tOCDTaSa/laO" +
            "hwHLJpRDvkWx3DVC53znwyguU/toOvBE0S5v0dm2ehaBUSoWcjCcNnKTAoGAavYp" +
            "uEbFRkVyEutee71C4tdbdv2+VQYbd4BjkFXLFpqpVEW9u03D59Ap83FJP2ArdWWY" +
            "dbPXzJ8kXw6L0m+lx4Q2XyjBmfCTkkKHqXXv7Y3s4/EZFdn2gpItJeY3uSIq9a9Y" +
            "IaW6/MkkQz7LodJNtHDtZRkhgaQxHn9KzyJdPoECgYEAs75ZaTk4JO9PsEwwokHq" +
            "LX59yk+g0NHf24vdDAQLXiEN1R6GezfFfW5RTZ1Z9EVtPqIlJ7ONLpXg0lEYol3P" +
            "iN/5yyqMuAaKpu6/2ESRPIG1xbn1yttyRusGqkD7G8cTi6FixjGLIeoQ9/0FaOPV" +
            "Jw7iHTfpu+iPQlmvb660GBs=";
}