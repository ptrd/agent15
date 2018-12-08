package net.luminis.tls;

import java.nio.ByteBuffer;

public class FinishedMessage {

    public void parse(ByteBuffer buffer, int i, TlsState state) {
        System.out.println("Got Finished message");
    }
}
