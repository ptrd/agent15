package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;

public class HandshakeRecord {

    byte[] data;

    public HandshakeRecord() {
    }

    public HandshakeRecord(ClientHello clientHello) {
        byte[] clientHelloData = clientHello.getBytes();

        ByteBuffer buffer = ByteBuffer.allocate(5 + clientHelloData.length);
        buffer.put(TlsConstants.ContentType.handshake.value);
        // https://tools.ietf.org/html/rfc8446#section-5.1:
        buffer.putShort((short) 0x0301);
        buffer.putShort((short) (clientHelloData.length));
        buffer.put(clientHelloData);

        data = buffer.array();
    }

    public void parse(PushbackInputStream input, TlsState state) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = input.read() << 8 | input.read();
        ByteBuffer buffer = ByteBuffer.allocate(length);
        input.read(buffer.array());

        parseHandshakeMessages(buffer, state);
    }


    static void parseHandshakeMessages(ByteBuffer buffer, TlsState state) throws TlsProtocolException {
        while (buffer.remaining() > 0) {
            buffer.mark();
            int messageType = buffer.get();
            int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
            buffer.reset();

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

    public byte[] getBytes() {
        return data;
    }
}
