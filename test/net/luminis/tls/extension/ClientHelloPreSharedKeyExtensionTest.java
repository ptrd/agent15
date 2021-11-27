package net.luminis.tls.extension;

import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsState;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.handshake.NewSessionTicketMessage;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;


class ClientHelloPreSharedKeyExtensionTest {

    @Test
    void testSerialize() throws Exception {
        var extension = new ClientHelloPreSharedKeyExtension(new NewSessionTicket(mock(TlsState.class),
                new NewSessionTicketMessage(3600, 0xffffffff, new byte[]{ 0x00 }, new byte[]{ 0x00, 0x01, 0x02, 0x03 })));
        byte[] data = extension.getBytes();

        assertThat(data).isEqualTo(ByteUtils.hexToBytes("0029 002f 000a 0004 00010203 ffffffff 0021 20 0000000000000000000000000000000000000000000000000000000000000000"));
    }

    @Test
    void parseSerializedExtension() throws Exception {

        var extension = new ClientHelloPreSharedKeyExtension(new NewSessionTicket(mock(TlsState.class),
                new NewSessionTicketMessage(3600, 0xca, new byte[]{ 0x00 }, new byte[]{ 0x00, 0x01, 0x02, 0x03 })));
        byte[] data = extension.getBytes();
        var parsedExtension = new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(data));
        assertThat(parsedExtension.getIdentities()).hasSize(1);
        assertThat(parsedExtension.getIdentities().get(0).getIdentity()).isEqualTo(new byte[]{ 0x00, 0x01, 0x02, 0x03 });
        assertThat(parsedExtension.getIdentities().get(0).getObfuscatedTicketAge()).isEqualTo(0xca);
        assertThat(parsedExtension.getBinders()).hasSize(1);
        assertThat(parsedExtension.getBinders().get(0).getHmac()).isEqualTo(new byte[32]);  // Mock TlsState will generate 0's
    }

    @Test
    void parseCorrectExtensionData() throws Exception {
        String rawBytes = "0029 003b 0016 0010 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        var parsedExtension = new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)));
        assertThat(parsedExtension.getIdentities()).hasSize(1);
        assertThat(parsedExtension.getIdentities().get(0).getObfuscatedTicketAge()).isEqualTo(0xffffffff);
        assertThat(parsedExtension.getBinders()).hasSize(1);
    }

    @Test
    void parseIncompleteExtension() throws Exception {
        String rawBytes = "0029 003b 0016 0010 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentIdentitiesLengths1() throws Exception {
        // if there is only one PskIdentify, the identities length field must be 6 larger then the identity length field: 4 bytes ticket_age and 2 bytes for the identify length itself
        String rawBytes = "0029 003b 0016 0011 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentIdentitiesLengths2() throws Exception {
        // if there is only one PskIdentify, the identities length field must be 6 larger then the identity length field: 4 bytes ticket_age and 2 bytes for the identify length itself
        String rawBytes = "0029 003b 0016 000f 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseIncorrectIdentitiesLength() throws Exception {
        // length field claims 18, but it is only 16
        String rawBytes = "0029 003b 0018 0012 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMissingBinderLength() throws Exception {
        // identity length: 40, psk-identity length (including age field): 46
        String rawBytes = "0029 0048 0046 0040 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f ffffffff";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMissingBinders() throws Exception {
        // identity length: 40, psk-identity length (including age field): 46
        String rawBytes = "0029 004a 0046 0040 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f ffffffff 0000";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentBinderLength() throws Exception {
        // i.e. extension length field does not completely cover the binders, it should be 2 + 0x46 + 0x23 = 0x6b
        String rawBytes = "0029 0061 0046 0040 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseIncorrectBinderLength() throws Exception {
        String rawBytes = "0029 006a 0046 0040 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentBinderLengths() throws Exception {
        String rawBytes = "0029 006b 0046 0040 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f ffffffff 0020 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        assertThatThrownBy(() ->
                        new ClientHelloPreSharedKeyExtension().parse(ByteBuffer.wrap(ByteUtils.hexToBytes(rawBytes)))
        ).isInstanceOf(DecodeErrorException.class);
    }
}