package net.luminis.tls;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions {

    public EncryptedExtensions parse(ByteBuffer buffer, int length, TlsState state) {

        System.out.println("Got Encrypted Extensions message (" + length + " bytes)");

        // Update state.
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setEncryptedExtensions(raw);

        return this;
    }
}
