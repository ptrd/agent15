package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;

public class HandshakeRecord {

    public void parse(PushbackInputStream input, TlsState state) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = input.read() << 8 | input.read();
        ByteBuffer buffer = ByteBuffer.allocate(length);
        input.read(buffer.array());

        while (buffer.remaining() > 0)
            parseHandshakeMessage(buffer, state);
    }

    static void parseHandshakeMessage(ByteBuffer buffer, TlsState state) throws TlsProtocolException {
        int messageType = buffer.get();
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        buffer.rewind();

        switch (messageType) {
            case 2:
                new ServerHello().parse(buffer, length + 4, state);
                break;
            case 8:
                new EncryptedExtensions().parse(buffer, length + 4, state);
                break;
            case 11:
                new CertificateMessage().parse(buffer, length + 4, state);
                break;
            case 15:
                new CertificateVerifyMessage().parse(buffer, length + 4, state);
                break;
            case 20:
                new FinishedMessage().parse(buffer, length + 4, state);
                break;
            case 1:
                // client hello
            default:
                throw new TlsProtocolException("Invalid/unsupported handshake message type (" + messageType + ")");
        }
    }
}
