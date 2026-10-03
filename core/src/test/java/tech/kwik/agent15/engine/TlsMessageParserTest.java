/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.handshake.HandshakeMessage;
import tech.kwik.agent15.handshake.HelloRetryRequest;
import tech.kwik.agent15.handshake.ServerHello;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

class TlsMessageParserTest {

    // region hello retry request
    @Test
    void parsingHelloRetryRequestShouldCallHelloRetryRequestReceivedMethod() throws Exception {
        // Given
        MessageProcessor messageProcessor = mockMessageProcessor();
        doNothing().when(messageProcessor).received(any(HelloRetryRequest.class), any(ProtectionKeysType.class));

        byte[] data = ByteUtils.hexToBytes(helloRetryRequestInHex());

        // When
        HandshakeMessage parsedMessage = new TlsMessageParser().parseAndProcessHandshakeMessage(ByteBuffer.wrap(data),
                messageProcessor, ProtectionKeysType.Handshake);

        // Then
        assertThat(parsedMessage).isInstanceOf(HelloRetryRequest.class);
        verify(messageProcessor).received(any(HelloRetryRequest.class), eq(ProtectionKeysType.Handshake));
        verify(messageProcessor, never()).received(any(ServerHello.class), any(ProtectionKeysType.class));
    }

    @Test
    void parsingServerHelloShouldCallServerHelloReceivedMethod() throws Exception {
        // Given
        MessageProcessor messageProcessor = mockMessageProcessor();

        byte[] data = ByteUtils.hexToBytes("02000077030327303877f58601e5e987b1be085f509adecd10056353daf3843f5f89084a4c6100130100004f002b0002030400330045001700410456517b9551d5ce0950c8210bf1f30b3f5d2b066ac6ac7469d6490387b36d9a57385bdfe2d5d55a1e6956a6d8d771cd7f1aee418b1cf615cbd976ba509a48e9de");

        // When
        HandshakeMessage parsedMessage = new TlsMessageParser().parseAndProcessHandshakeMessage(ByteBuffer.wrap(data),
                messageProcessor, ProtectionKeysType.Handshake);

        // Then
        assertThat(parsedMessage).isInstanceOf(ServerHello.class);
        verify(messageProcessor).received(any(ServerHello.class), eq(ProtectionKeysType.Handshake));
        verify(messageProcessor, never()).received(any(HelloRetryRequest.class), any(ProtectionKeysType.class));
    }
    // endregion

    /**
     * Creates a MessageProcessor mock that executes the (default) methods of the interface, so the dispatching done by
     * <code>received(HandshakeMessage, ProtectionKeysType)</code> is actually performed.
     */
    private MessageProcessor mockMessageProcessor() {
        return mock(MessageProcessor.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
    }

    /**
     * A HelloRetryRequest: a server_hello message whose random field holds the fixed HelloRetryRequest value, see
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3.
     */
    private String helloRetryRequestInHex() {
        String helloRetryRequestRandom = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";
        //      type length legacy_v  random                     session_id cipher cmp
        return ("02  000034  0303 " + helloRetryRequestRandom + "  00        1301   00"
                //  extensions: length supported versions  key share (selected group: x25519)
                + "                    000c   002b00020304        00330002001d").replaceAll(" ", "");
    }
}
