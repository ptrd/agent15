package net.luminis.tls;

import net.luminis.tls.exception.MissingExtensionAlert;
import net.luminis.tls.extension.SupportedVersionsExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
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
    void afterProperSserverHelloSelectedCipherIsAvailable() throws Exception {
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



}