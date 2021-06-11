/*
 * Copyright © 2021 Peter Doornbosch
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

import net.luminis.tls.TlsConstants;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.extension.SignatureAlgorithmsExtension;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateRequestMessageTest {

    @Test
    void parseValidMessage() throws Exception {
        //                                                 |-> extension, 30 bytes
        var data = ByteUtils.hexToBytes("0d00002100001e002f001a0018001630143112301006035504030c096c6f63616c686f7374");
        ByteBuffer buffer = ByteBuffer.wrap(data);
        var message = new CertificateRequestMessage().parse(buffer);

        assertThat(message.getExtensions()).hasSize(1);
        assertThat(buffer.remaining()).isEqualTo(0);
    }

    @Test
    void serializeMessage() throws Exception {
        var originalMessage = new CertificateRequestMessage(new SignatureAlgorithmsExtension(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256));
        var serializedMessage = originalMessage.getBytes();
        ByteBuffer buffer = ByteBuffer.wrap(serializedMessage);
        var parsedMessage = new CertificateRequestMessage().parse(buffer);

        assertThat(serializedMessage).startsWith(new byte[] { 0x0d });
        assertThat(buffer.remaining()).isEqualTo(0);
        assertThat(Arrays.copyOfRange(serializedMessage, 4, 5)).isEqualTo(new byte[] { 0 });  // certificate_request_context length
        assertThat(parsedMessage.getExtensions())
                .hasSize(1)
                .hasOnlyElementsOfType(SignatureAlgorithmsExtension.class);
    }

    @Test
    void parseMessageWithInCorrectLength() throws Exception {
        //                                                 |-> extension, 30 bytes
        var data = ByteUtils.hexToBytes("0d00002000001e002f001a0018001630143112301006035504030c096c6f63616c686f7374");

        assertThatThrownBy(() ->
                new CertificateRequestMessage().parse(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }

        @Test
    void parseMessageWithInvalidExtensionLength() throws Exception {
        //                                                 |-> extension, 30 bytes
        var data = ByteUtils.hexToBytes("0d00002100001d002f001a0018001630143112301006035504030c096c6f63616c686f7374");

        assertThatThrownBy(() ->
                new CertificateRequestMessage().parse(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }
}
