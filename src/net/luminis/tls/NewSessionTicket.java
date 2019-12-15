package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.Date;


public class NewSessionTicket {

    private byte[] psk;
    private Date ticketCreationDate;
    private long ticketAgeAdd;
    private byte[] ticket;
    private int ticketLifeTime;

    public NewSessionTicket(TlsState state, NewSessionTicketMessage newSessionTicketMessage) {
        psk = state.computePSK(newSessionTicketMessage.getTicketNonce());
        ticketCreationDate = new Date();
        ticketAgeAdd = newSessionTicketMessage.getTicketAgeAdd();
        ticket = newSessionTicketMessage.getTicket();
        ticketLifeTime = newSessionTicketMessage.getTicketLifetime();
    }

    private NewSessionTicket(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        ticketCreationDate = new Date(buffer.getLong());
        ticketAgeAdd = buffer.getLong();
        int ticketSize = buffer.getInt();
        ticket = new byte[ticketSize];
        buffer.get(ticket);
        int pskSize = buffer.getInt();
        psk = new byte[pskSize];
        buffer.get(psk);
        if (buffer.remaining() > 0) {
            ticketLifeTime = buffer.getInt();
        }
    }

    public static NewSessionTicket deserialize(byte[] data) {
        return new NewSessionTicket(data);
    }

    public byte[] serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.putLong(ticketCreationDate.getTime());
        buffer.putLong(ticketAgeAdd);
        buffer.putInt(ticket.length);
        buffer.put(ticket);
        buffer.putInt(psk.length);
        buffer.put(psk);
        buffer.putInt(ticketLifeTime);

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
    }

    int validFor() {
        return Integer.max(0, (int) ((ticketCreationDate.getTime() + ticketLifeTime * 1000) - new Date().getTime()) / 1000);
    }

    public byte[] getPSK() {
        return psk;
    }

    public Date getTicketCreationDate() {
        return ticketCreationDate;
    }

    public long getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    public byte[] getSessionTicketIdentity() {
        return ticket;
    }

    @Override
    public String toString() {
        return "Ticket, creation date = " + ticketCreationDate + ", ticket lifetime = " + ticketLifeTime
                + (validFor() > 0 ? " (still valid for " + validFor() + " seconds)": " (not valid anymore)");
    }
}
