package net.luminis.tls.extension;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.DecodeErrorException;
import net.luminis.tls.TlsConstants;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class PskKeyExchangeModesExtensionTest {

    @Test
    void testParseSinglePskMode() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d00020101"));

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes()).containsExactly(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testParseMultiplePskModes() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d0003020001"));

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes())
                .containsExactlyInAnyOrder(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testSerializeSinglePskMode() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke).getBytes());

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes()).containsExactly(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testSerializeMultiplePskModes() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke).getBytes());

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes())
                .containsExactlyInAnyOrder(TlsConstants.PskKeyExchangeMode.psk_dhe_ke, TlsConstants.PskKeyExchangeMode.psk_ke);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d000201"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInvalidDataLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d000201"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

}