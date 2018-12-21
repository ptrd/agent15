package net.luminis.tls;

import java.nio.ByteBuffer;

public class FinishedMessage {

    public FinishedMessage parse(ByteBuffer buffer, int length, TlsState state) {
        for (int i = 0; i < length; i++)
            buffer.get();
        System.out.println("Got Finished message (" + length + " bytes)");
        return this;
    }
}
