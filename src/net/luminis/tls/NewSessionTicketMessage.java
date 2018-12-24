package net.luminis.tls;

import java.nio.ByteBuffer;

public class NewSessionTicketMessage {

    public NewSessionTicketMessage parse(ByteBuffer buffer, int length, TlsState state) {
        for (int i = 0; i < length; i++)
            buffer.get();
        System.out.println("Got New Session Ticket message (" + length + " bytes)");

        return this;
    }
}
