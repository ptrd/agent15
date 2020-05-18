package net.luminis.tls;

import net.luminis.tls.exception.MissingExtensionAlert;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static net.luminis.tls.TlsConstants.CipherSuite.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class TlsClientEngineTest {

    private TlsClientEngine engine;

    @BeforeEach
    private void initObjectUnderTest() {
        engine = new TlsClientEngine(mock(ClientMessageSender.class));
        engine.setServerName("server");
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
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
    void engineAcceptsCorrectServerHello() throws Exception {
        // Given
        engine.startHandshake();

        ServerHello serverHello = new ServerHello(TLS_AES_128_GCM_SHA256, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new ServerPreSharedKeyExtension()));

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
                new ServerPreSharedKeyExtension()));
        engine.received(serverHello);

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void afterProperServerHelloTrafficSecretsAreAvailable() throws Exception {
        // Given
        ECPublicKey publicKey = (ECPublicKey) generateKeys()[1];
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

}