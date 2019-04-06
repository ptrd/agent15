package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.Date;

public class NewSessionTicket {

    private final TlsState state;
    private final NewSessionTicketMessage newSessionTicketMessage;

    public NewSessionTicket(TlsState state, NewSessionTicketMessage newSessionTicketMessage) {
        this.state = state;
        this.newSessionTicketMessage = newSessionTicketMessage;
    }

    public byte[] serialize() {
        byte[] psk = state.computePSK(newSessionTicketMessage.getTicketNonce());

        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.putLong(new Date().getTime());
        buffer.putInt((int) newSessionTicketMessage.getTicketAgeAdd());
        buffer.putInt(newSessionTicketMessage.getTicket().length);
        buffer.put(newSessionTicketMessage.getTicket());
        buffer.putInt(psk.length);
        buffer.put(psk);

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
    }
}
