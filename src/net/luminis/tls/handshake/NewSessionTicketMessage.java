/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.tls.*;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.alert.UnsupportedExtensionAlert;
import net.luminis.tls.extension.EarlyDataExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.UnknownExtension;

import java.nio.ByteBuffer;
import java.util.List;

// https://tools.ietf.org/html/rfc8446#section-4.6.1
public class NewSessionTicketMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 4 + 4 + 1 + 2 + 2;

    private long ticketAgeAdd;
    private byte[] ticket;
    private byte[] ticketNonce;
    private int ticketLifetime;
    // "The sole extension currently defined for NewSessionTicket is "early_data", ..."
    private EarlyDataExtension earlyDataExtension;


    public NewSessionTicketMessage() {
    }

    public NewSessionTicketMessage(int ticketLifetime, long ticketAgeAdd, byte[] ticketNonce, byte[] ticket) {
        this.ticketAgeAdd = ticketAgeAdd;
        this.ticket = ticket;
        this.ticketNonce = ticketNonce;
        this.ticketLifetime = ticketLifetime;
    }

    public NewSessionTicketMessage(int ticketLifetime, long ticketAgeAdd, byte[] ticketNonce, byte[] ticket, long maxEarlyDataSize) {
        this.ticketAgeAdd = ticketAgeAdd;
        this.ticket = ticket;
        this.ticketNonce = ticketNonce;
        this.ticketLifetime = ticketLifetime;
        earlyDataExtension = new EarlyDataExtension(maxEarlyDataSize);
    }

    public NewSessionTicketMessage parse(ByteBuffer buffer) throws TlsProtocolException {
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.new_session_ticket, MINIMUM_MESSAGE_SIZE);

        // "ticket_lifetime: Indicates the lifetime in seconds as a 32-bit unsigned integer (...)"
        // "Servers MUST NOT use any value greater than 604800 seconds (7 days)."
        // So a signed int is large enough to hold the unsigned value.
        ticketLifetime = buffer.getInt();
        remainingLength -= 4;
        if (ticketLifetime > 604800 || ticketLifetime < 0) {
            throw new IllegalParameterAlert("Invalid ticket lifetime");
        }
        // "ticket_age_add: A securely generated, random 32-bit value that is used to obscure the age of the ticket"
        ticketAgeAdd = buffer.getInt() & 0xffffffffL;
        remainingLength -= 4;
        // "ticket_nonce: A per-ticket value that is unique across all tickets issued on this connection."
        ticketNonce = parseByteVector(buffer, 1, remainingLength, "ticket nonce");
        remainingLength -= 1 + ticketNonce.length;
        // "ticket: The value of the ticket to be used as the PSK identity."
        ticket = parseByteVector(buffer, 2, remainingLength, "ticket");

        List<Extension> extensions = EncryptedExtensions.parseExtensions(buffer, TlsConstants.HandshakeType.new_session_ticket);
        for (Extension extension: extensions) {
            if (extension instanceof EarlyDataExtension) {
                if (earlyDataExtension == null) {
                    earlyDataExtension = (EarlyDataExtension) extension;
                }
                else {
                    throw new UnsupportedExtensionAlert("Only one early data extension is allowed");
                }
            }
            else if (extension instanceof UnknownExtension) {
                int type = ((UnknownExtension) extension).getType();
                // https://tools.ietf.org/html/rfc8701
                // The following values are reserved as GREASE values for extensions (...):
                // 0x0A0A  0x1A1A  0x2A2A  0x3A3A  0x4A4A  0x5A5A  0x6A6A  0x7A7A  0x8A8A  0x9A9A  0xAAAA  0xBABA  0xCACA  0xDADA  0xEAEA  0xFAFA
                if ((type & 0x0a0a) != 0x0a0a) {
                    throw new UnsupportedExtensionAlert("Only early data extension is allowed");
                }
            }
        }

        return this;
    }

    private byte[] parseByteVector(ByteBuffer buffer, int lengthBytes, int remainingMessageLength, String fieldName) throws DecodeErrorException {
        if (remainingMessageLength < lengthBytes) {
            throw new DecodeErrorException("No length specified for " + fieldName);
        }
        int vectorSize = 0;
        for (int i = 0; i < lengthBytes; i++) {
            vectorSize = (vectorSize << 8) | buffer.get() & 0xff;
        }
        remainingMessageLength -= lengthBytes;
        if (remainingMessageLength < vectorSize) {
            throw new DecodeErrorException("Message too short for given length of " + fieldName);
        }
        byte[] byteVector = new byte[vectorSize];
        buffer.get(byteVector);
        return byteVector;
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.new_session_ticket;
    }

    @Override
    public byte[] getBytes() {
        int extensionLength = earlyDataExtension != null? earlyDataExtension.getBytes().length: 0;
        int dataLength = 4 + 4 + 1 + ticketNonce.length + 2 + ticket.length + 2 + extensionLength;
        ByteBuffer buffer = ByteBuffer.allocate(4 + dataLength);
        buffer.putInt((TlsConstants.HandshakeType.new_session_ticket.value << 24) | dataLength);
        buffer.putInt(ticketLifetime);
        buffer.putInt((int) ticketAgeAdd);
        buffer.put((byte) ticketNonce.length);
        buffer.put(ticketNonce);
        buffer.putShort((short) ticket.length);
        buffer.put(ticket);
        buffer.putShort((short) extensionLength);
        if (earlyDataExtension != null) {
            buffer.put(earlyDataExtension.getBytes());
        }

        return buffer.array();
    }

    public int getTicketLifetime() {
        return ticketLifetime;
    }

    public long getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    public byte[] getTicket() {
        return ticket;
    }

    public byte[] getTicketNonce() {
        return ticketNonce;
    }

    public EarlyDataExtension getEarlyDataExtension() {
        return earlyDataExtension;
    }
}
