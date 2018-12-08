package net.luminis.tls;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions {

    public void parse(ByteBuffer buffer, int i, TlsState state) {
        System.out.println("Got Encrypted Extensions message");
    }
}
