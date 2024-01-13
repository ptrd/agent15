/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.extension.EarlyDataExtension;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NewSessionTicketMessageTest {

    @Test
    void parseValidMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400004f 00093a80 fab00e11 04 01020304 0040 " + "00".repeat(64) + "0000");
        NewSessionTicketMessage message = new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData));

        assertThat(message.getTicketLifetime()).isEqualTo(604800);
        assertThat(message.getTicketNonce()).isEqualTo(new byte[] { 1, 2, 3, 4});
        assertThat(message.getTicket()).hasSize(64);
    }

    @Test
    void parseMessageWithIllegalTicketLifetime() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400004f 00093a81 fab00e11 04 01020304 0040 " + "00".repeat(64) + "0000");

        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void whenParsingMessageInappropriateExtensionShouldBeIgnored() throws Exception {
        //                                              lifetime age_add  nonce       ticket        exts ext_1     ext_2
        byte[] rawData = ByteUtils.hexToBytes("0400001d 00093a80 fab00e11 04 01020304 0004 01020304 000c fab0 0000 002a 0004 01020304");

        NewSessionTicketMessage newSessionTicketMessage = new NewSessionTicketMessage();

        assertThatCode(() ->
                newSessionTicketMessage.parse(ByteBuffer.wrap(rawData)))
                .doesNotThrowAnyException();

        assertThat(newSessionTicketMessage.getEarlyDataExtension()).isNotNull();
    }

    @Test
    void whenParsingMessageRepeatedExtensionShouldThrow() throws Exception {
        //                                              lifetime age_add  nonce       ticket        exts ext 1              ext 2
        byte[] rawData = ByteUtils.hexToBytes("04000022 00093a80 fab00e11 04 01020304 0004 01020304 0010 002a 0004 01020304 002a 0004 01020304");

        NewSessionTicketMessage newSessionTicketMessage = new NewSessionTicketMessage();

        assertThatThrownBy(() ->
                newSessionTicketMessage.parse(ByteBuffer.wrap(rawData)))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseNoMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0400");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMessageWithInconsistentNonceLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("04000017 0000cafe cafebabe ff 01020304 0008 0102030405060708");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseMessageWithInconsistentTicketLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("04000017 0000cafe cafebabe 04 01020304 04ff 0102030405060708");
        assertThatThrownBy(() ->
                new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void newSessionTicketMessageMayContainGreasedExtensionType() throws Exception {
        // ...                                          lifetime age_add  nonce       ticket
        byte[] rawData = ByteUtils.hexToBytes("0400001f 00093a80 fab00e11 04 01020304 0004 01020304"
                // extensions length
                + "000c"
                + "baba 0000"
                + "002a 0004 01ff ffff"
        );

        EarlyDataExtension earlyDataExtension = new NewSessionTicketMessage().parse(ByteBuffer.wrap(rawData)).getEarlyDataExtension();

        assertThat(earlyDataExtension).isNotNull();
    }

    @Test
    void testSerializedMessageCanBeParsedCorrectly() throws Exception {
        int lifetime = 604800;
        int ageAdd = 12341234;
        byte[] nonce = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
        byte[] ticket = new byte[] { 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e };
        NewSessionTicketMessage message = new NewSessionTicketMessage(lifetime, ageAdd, nonce, ticket);
        byte[] serializedMsg = message.getBytes();
        NewSessionTicketMessage parsedMsg = new NewSessionTicketMessage();
        parsedMsg.parse(ByteBuffer.wrap(serializedMsg));

        assertThat(parsedMsg.getTicketLifetime()).isEqualTo(lifetime);
        assertThat(parsedMsg.getTicketAgeAdd()).isEqualTo(ageAdd);
        assertThat(parsedMsg.getTicketNonce()).isEqualTo(nonce);
        assertThat(parsedMsg.getTicket()).isEqualTo(ticket);
    }

    @Test
    void testSerializedMessageWithEarlyDataExtensionCanBeParsedCorrectly() throws Exception {
        int lifetime = 604800;
        int ageAdd = 12341234;
        byte[] nonce = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
        byte[] ticket = new byte[] { 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e, 0x0d, 0x0e };
        long maxEarlyDataSize = 0x90008000L;
        NewSessionTicketMessage message = new NewSessionTicketMessage(lifetime, ageAdd, nonce, ticket, maxEarlyDataSize);
        byte[] serializedMsg = message.getBytes();
        NewSessionTicketMessage parsedMsg = new NewSessionTicketMessage();
        parsedMsg.parse(ByteBuffer.wrap(serializedMsg));

        assertThat(parsedMsg.getTicketLifetime()).isEqualTo(lifetime);
        assertThat(parsedMsg.getTicketAgeAdd()).isEqualTo(ageAdd);
        assertThat(parsedMsg.getTicketNonce()).isEqualTo(nonce);
        assertThat(parsedMsg.getTicket()).isEqualTo(ticket);
        assertThat(parsedMsg.getEarlyDataExtension()).isNotNull();
        assertThat(parsedMsg.getEarlyDataExtension().getMaxEarlyDataSize()).isEqualTo(0x90008000L);
    }
}
