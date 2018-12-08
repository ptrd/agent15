package net.luminis.tls;

import java.nio.ByteBuffer;

public class CertificateMessage {

    public void parse(ByteBuffer buffer, int i, TlsState state) {
        System.out.println("Got Certificate message");
    }
}
