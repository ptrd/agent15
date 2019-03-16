package net.luminis.tls;

import java.nio.ByteBuffer;

public class NewSessionTicketMessage extends HandshakeMessage {

    private long ticketAgeAdd;
    private byte[] ticket;
    private byte[] ticketNonce;

    private long ticketLifetime;

    public NewSessionTicketMessage parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {
        buffer.getInt();  // Skip message type and 3 bytes length

        ticketLifetime = buffer.getInt() & 0xffffffffL;
        ticketAgeAdd = buffer.getInt() & 0xffffffffL;
        int ticketNonceSize = buffer.get() & 0xff;
        ticketNonce = new byte[ticketNonceSize];
        buffer.get(ticketNonce);
        int ticketSize = buffer.getShort() & 0xffff;
        ticket = new byte[ticketSize];
        buffer.get(ticket);

        EncryptedExtensions.parseExtensions(buffer);

        Logger.debug("Got New Session Ticket message (" + length + " bytes)");
        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public long getTicketLifetime() {
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
}
