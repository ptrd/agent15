package net.luminis.tls;

import net.luminis.tls.extension.Extension;

import java.nio.ByteBuffer;
import java.util.List;

public class NewSessionTicketMessage extends HandshakeMessage {

    private long ticketAgeAdd;
    private byte[] ticket;
    private byte[] ticketNonce;
    private int ticketLifetime;
    // https://tools.ietf.org/html/rfc8446#section-4.6.1
    // "The sole extension currently defined for NewSessionTicket is "early_data", ..."
    private EarlyDataExtension earlyDataExtension;

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

        List<Extension> extensions = EncryptedExtensions.parseExtensions(buffer, TlsConstants.HandshakeType.new_session_ticket);
        if (! extensions.isEmpty()) {
            if (extensions.get(0) instanceof EarlyDataExtension) {
                earlyDataExtension = (EarlyDataExtension) extensions.get(0);
            } else {
                Logger.debug("Unexpected extension type in NewSessionTicketMessage: " + extensions.get(0));
            }
        }

        Logger.debug("Got New Session Ticket message (" + length + " bytes)");
        return this;
    }

    @Override
    TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.new_session_ticket;
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

    public EarlyDataExtension getEarlyDataExtension() {
        return earlyDataExtension;
    }
}
