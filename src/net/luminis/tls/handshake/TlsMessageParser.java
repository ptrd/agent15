/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.tls.ProtectionKeysType;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.extension.ExtensionParser;

import java.io.IOException;
import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.HandshakeType.*;

public class TlsMessageParser {

    private final ExtensionParser customExtensionParser;

    public TlsMessageParser() {
        customExtensionParser = null;
    }

    public TlsMessageParser(ExtensionParser customExtensionParser) {
        this.customExtensionParser = customExtensionParser;
    }

    public HandshakeMessage parseAndProcessHandshakeMessage(ByteBuffer buffer, MessageProcessor messageProcessor, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        // https://tools.ietf.org/html/rfc8446#section-4
        // "      struct {
        //          HandshakeType msg_type;    /* handshake type */
        //          uint24 length;             /* remaining bytes in message */
        //          ...
        //      } Handshake;"
        buffer.mark();
        int messageType = buffer.get();
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        buffer.reset();

        HandshakeMessage parsedMessage;
        if (messageType == client_hello.value) {
            ClientHello ch = new ClientHello(buffer, customExtensionParser);
            parsedMessage = ch;
            messageProcessor.received(ch, protectedBy);
        }
        else if (messageType == server_hello.value) {
            ServerHello sh = new ServerHello().parse(buffer, length + 4);
            parsedMessage = sh;
            messageProcessor.received(sh, protectedBy);
        }
        else if (messageType == encrypted_extensions.value) {
            EncryptedExtensions ee = new EncryptedExtensions().parse(buffer, length + 4, customExtensionParser);
            parsedMessage = ee;
            messageProcessor.received(ee, protectedBy);
        }
        else if (messageType == certificate.value) {
            CertificateMessage cm = new CertificateMessage().parse(buffer);
            parsedMessage = cm;
            messageProcessor.received(cm, protectedBy);
        }
        else if (messageType == certificate_request.value) {
            CertificateRequestMessage cr = new CertificateRequestMessage().parse(buffer);
            parsedMessage = cr;
            messageProcessor.received(cr, protectedBy);
        }
        else if (messageType == certificate_verify.value) {
            CertificateVerifyMessage cv = new CertificateVerifyMessage().parse(buffer, length + 4);
            parsedMessage = cv;
            messageProcessor.received(cv, protectedBy);
        }
        else if (messageType == finished.value) {
            FinishedMessage fm = new FinishedMessage().parse(buffer, length + 4);
            parsedMessage = fm;
            messageProcessor.received(fm, protectedBy);
        }
        else if (messageType == new_session_ticket.value) {
            NewSessionTicketMessage nst = new NewSessionTicketMessage().parse(buffer);
            parsedMessage = nst;
            messageProcessor.received(nst, protectedBy);
        }
        else {
            throw new TlsProtocolException("Invalid/unsupported message type (" + messageType + ")");
        }
        return parsedMessage;
    }

}
