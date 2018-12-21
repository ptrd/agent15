package net.luminis.tls;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions {

    public EncryptedExtensions parse(ByteBuffer buffer, int length, TlsState state) {
        for (int i = 0; i < length; i++)
            buffer.get();
        System.out.println("Got Encrypted Extensions message (" + length + " bytes)");
        return this;
    }
}
