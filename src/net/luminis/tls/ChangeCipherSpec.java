package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;

public class ChangeCipherSpec {

    public void parse(PushbackInputStream input) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = (input.read() << 8) | input.read();

        if (length != 1)
            throw new TlsProtocolException("change_cipher_spec must have value 0x01");

        byte[] data = new byte[length];
        int count = input.read(data);
        while (count != length) {
            count += input.read(data, count, length - count);
        }

        Logger.debug("Got ChangeCipherSpec message");
    }
}
