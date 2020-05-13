package net.luminis.tls.extension;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.DecodeErrorException;
import net.luminis.tls.TlsConstants;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class SupportedVersionsExtensionTest {

    @Test
    void testParseVersionExtensionInServerHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00020304"));

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testParseVersionExtensionInClientHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b0003020304"));

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testSerializeVersionExtensionInClientHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello).getBytes());

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testSerializeVersionExtensionInServerHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello).getBytes());

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00030203"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowClientHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00020103"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowServerHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b000103"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInconsistentLengthsClientHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00030403040303"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInconsistentLengthsServerHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b000403040303"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }
}