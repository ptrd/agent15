package net.luminis.tls;

import java.nio.ByteBuffer;

public class NewSessionTicketMessage extends HandshakeMessage {

    public NewSessionTicketMessage parse(ByteBuffer buffer, int length, TlsState state) {
        for (int i = 0; i < length; i++)
            buffer.get();
        Logger.debug("Got New Session Ticket message (" + length + " bytes)");

        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
