package net.luminis.tls;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

class NewSessionTicketMessageTest {

    @Test
    void parseValidMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400004f 00093a80 fab00e11 04 01020304 0040 " + "00".repeat(64) + "0000");
        NewSessionTicketMessage message = new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length);

        assertThat(message.getTicketLifetime()).isEqualTo(604800);
        assertThat(message.getTicketNonce()).isEqualTo(new byte[] { 1, 2, 3, 4});
        assertThat(message.getTicket()).hasSize(64);
    }

    @Test
    void parseMessageWithIllegalTicketLifetime() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400004f 00093a81 fab00e11 04 01020304 0040 " + "00".repeat(64) + "0000");

        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseMessageWithInappropriateExtension() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("04000017 00093a80 fab00e11 04 01020304 0004 01020304 0004 fab0 0000");

        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length)
        ).isInstanceOf(UnsupportedExtensionAlert.class);
    }

    @Test
    void parseNoMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMessageWithInconsistentNonceLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("04000017 0000cafe cafebabe ff 01020304 0008 0102030405060708");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMessageWithInconsistentTicketLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("04000017 0000cafe cafebabe 04 01020304 04ff 0102030405060708");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void newSessionTicketMessageMayContainGreasedExtensionType() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400001f 00093a80 fab00e11 04 01020304 0004 01020304"
                + "000a"
                + "baba 0000"
                + "002a 0004 01ff ffff"
        );

        EarlyDataExtension earlyDataExtension = new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData), rawData.length).getEarlyDataExtension();

        assertThat(earlyDataExtension).isNotNull();
    }
}
