package net.luminis.tls;

import java.nio.ByteBuffer;

public class CertificateVerifyMessage {

    public void parse(ByteBuffer buffer, int i, TlsState state) {
        System.out.println("Got Certificate Verify message");
    }
}
