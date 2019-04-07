package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.Date;


public class NewSessionTicket {

    private final TlsState state;
    private NewSessionTicketMessage newSessionTicketMessage;

    private byte[] psk;
    private Date ticketCreationDate;
    private long ticketAgeAdd;
    private byte[] ticket;

    public NewSessionTicket(TlsState state, NewSessionTicketMessage newSessionTicketMessage) {
        this.state = state;
        this.newSessionTicketMessage = newSessionTicketMessage;
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

        state = null;
    }

    public static NewSessionTicket deserialize(byte[] data) {
        return new NewSessionTicket(data);
    }

    public byte[] serialize() {
        byte[] psk = state.computePSK(newSessionTicketMessage.getTicketNonce());

        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.putLong(new Date().getTime());
        buffer.putLong(newSessionTicketMessage.getTicketAgeAdd());
        buffer.putInt(newSessionTicketMessage.getTicket().length);
        buffer.put(newSessionTicketMessage.getTicket());
        buffer.putInt(psk.length);
        buffer.put(psk);

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
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
}
