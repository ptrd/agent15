package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;

public class ApplicationData {

    public void parse(PushbackInputStream input, TlsState state) throws TlsProtocolException, IOException {
        byte[] recordHeader = new byte[5];
        input.read(recordHeader);
        input.unread(recordHeader);

        input.read();  // message type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = input.read() << 8 | input.read();
        ByteBuffer buffer = ByteBuffer.allocate(length);
        input.read(buffer.array());

        System.out.println("Received application data: ");
        System.out.println(ByteUtils.bytesToHex(buffer.array()));

        byte[] decryptedData = state.decrypt(recordHeader, buffer.array());
        System.out.println("Decrypted: " + ByteUtils.bytesToHex(decryptedData));

        // TODO: remove padding, see https://tools.ietf.org/html/rfc8446#section-5.4
        parseMessage(decryptedData, state);
    }

    private void parseMessage(byte[] message, TlsState state) throws TlsProtocolException {
        int lastByte = message[message.length-1];
        switch (lastByte) {
            case 22:
                HandshakeRecord.parseHandshakeMessages(ByteBuffer.wrap(message, 0, message.length - 1), state);
                break;
            default:
                throw new RuntimeException("Unexpected record type in Application Data: " + lastByte);
        }

    }
}
