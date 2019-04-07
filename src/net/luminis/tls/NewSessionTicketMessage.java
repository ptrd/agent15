package net.luminis.tls;

import java.nio.ByteBuffer;

public class NewSessionTicketMessage extends HandshakeMessage {

    private long ticketAgeAdd;
    private byte[] ticket;
    private byte[] ticketNonce;
    private int ticketLifetime;

    public NewSessionTicketMessage parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {
        buffer.getInt();  // Skip message type and 3 bytes length

        // https://www.davidwong.fr/tls13/#section-4.6.1
        // "Servers MUST NOT use any value greater than 604800 seconds (7 days)."
        // So a signed int is large enough to hold the unsigned value.
        ticketLifetime = buffer.getInt();
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
}
