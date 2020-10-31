package net.luminis.tls.extension;

import net.luminis.tls.util.ByteUtils;
import net.luminis.tls.alert.DecodeErrorException;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServerNameExtensionTest {

    @Test
    void parseServerNameExtension() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009" + "6c6f63616c686f7374"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isEqualToIgnoringCase("localhost");
    }

    @Test
    void serializeServerNameExtension() throws Exception {
        byte[] serializedData = new ServerNameExtension("localhost").getBytes();

        ServerNameExtension serverNameExtension = new ServerNameExtension(ByteBuffer.wrap(serializedData));

        assertThat(serverNameExtension.getHostName()).isEqualToIgnoringCase("localhost");
        assertThat(serializedData).startsWith(0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09);
    }

    @Test
    void parseUnderflow1() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseUnderflow2() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009" + "6c6f63616c686f73"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLength1() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000b" + "00" + "0009" + "6c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLength2() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0007" + "6c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEmptyExtension() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("00000000"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isNull();
    }

    @Test
    void extensionShouldHaveAtLeastSizeTwoWhenNotEmpty() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000000100"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

}