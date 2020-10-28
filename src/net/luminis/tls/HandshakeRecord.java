package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.*;

public class HandshakeRecord {

    private byte[] data;


    public HandshakeRecord() {
    }

    public HandshakeRecord(ClientHello clientHello) {
        byte[] clientHelloData = clientHello.getBytes();

        ByteBuffer buffer = ByteBuffer.allocate(5 + clientHelloData.length);
        buffer.put(ContentType.handshake.value);
        // https://tools.ietf.org/html/rfc8446#section-5.1:
        buffer.putShort((short) 0x0301);
        buffer.putShort((short) (clientHelloData.length));
        buffer.put(clientHelloData);

        data = buffer.array();
    }

    public HandshakeRecord parse(PushbackInputStream input, TlsClientEngine tlsClientEngine) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = input.read() << 8 | input.read();

        byte[] data = new byte[length];
        int count = input.read(data);
        while (count != length) {
            count += input.read(data, count, length - count);
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);

        TlsMessageParser parser = new TlsMessageParser();
        while (buffer.remaining() > 0) {
            parser.parseAndProcessHandshakeMessage(buffer, tlsClientEngine);
        }

        return this;
    }

    public byte[] getBytes() {
        return data;
    }

}
