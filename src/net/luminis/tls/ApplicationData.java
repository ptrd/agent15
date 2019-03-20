package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static net.luminis.tls.TlsConstants.ContentType.application_data;

public class ApplicationData {

    private byte[] recordBytes;

    public ApplicationData() {
    }

    /**
     * Wraps a TLS message in a TLS 1.2 compatible Application Data Record.
     * @param message
     * @param state
     */
    public ApplicationData(HandshakeMessage message, TlsState state) {
        this(message.getBytes(), state, TlsConstants.ContentType.handshake);
    }

    /**
     * Wraps application data in a TLS 1.2 compatible Application Data Record.
     * @param data
     * @param state
     */
    public ApplicationData(byte[] data, TlsState state) {
        this(data, state, application_data);
    }

    private ApplicationData(byte[] data, TlsState state, TlsConstants.ContentType contentType) {
        ByteBuffer buffer = ByteBuffer.allocate(5);

        buffer.put(application_data.value);
        buffer.put(new byte[] { 0x03, 0x03 });
        int payloadLength = data.length + 16 + 1;  // AEAD adds 16 bytes, 1 byte "inner content type"
        buffer.putShort((short) payloadLength);

        byte[] recordHeader = buffer.array();
        byte[] payload = new byte[data.length + 1];
        System.arraycopy(data, 0, payload, 0, data.length);
        payload[payload.length - 1] = contentType.value;
        Logger.debug("Before encrypting: " + ByteUtils.bytesToHex(payload));
        byte[] encryptedPayload = state.encryptPayload(payload, recordHeader);

        recordBytes = new byte[5 + payloadLength];
        buffer.rewind();
        buffer.get(recordBytes, 0, 5);
        System.arraycopy(encryptedPayload, 0, recordBytes, 5, encryptedPayload.length);
    }

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

        Logger.debug("Received Application Data bytes: ");
        Logger.debug(ByteUtils.bytesToHex(buffer.array()));

        byte[] decryptedData = state.decrypt(recordHeader, buffer.array());
        Logger.debug("Decrypted: " + ByteUtils.bytesToHex(decryptedData));

        // TODO: remove padding, see https://tools.ietf.org/html/rfc8446#section-5.4
        parseMessage(decryptedData, state);
    }

    private void parseMessage(byte[] message, TlsState state) throws TlsProtocolException {
        int lastByte = message[message.length-1];
        if (lastByte == TlsConstants.ContentType.handshake.value) {
            Logger.debug("Decrypted Application Data content is Handshake record.");
            ByteBuffer buffer = ByteBuffer.wrap(message, 0, message.length - 1);
            while (buffer.remaining() > 0) {
                HandshakeRecord.parseHandshakeMessage(buffer, state);
            }
        }
        else if (lastByte == TlsConstants.ContentType.alert.value) {
            Logger.debug("Decrypted Application Data content is Alert record.");
            ByteBuffer alert = ByteBuffer.wrap(message, 0, message.length - 1);
            AlertRecord.parseAlertMessage(alert);
        }
        else if (lastByte == application_data.value) {
            Logger.debug("Decrypted Application Data content is Application Data record");
            String content = new String(message, 0, message.length - 1, Charset.forName("UTF-8"));
            Logger.debug("Content:");
            Logger.debug(content);
        }
        else {
            throw new RuntimeException("Unexpected record type in Application Data: " + lastByte);
        }
    }

    public byte[] getBytes() {
        return recordBytes;
    }
}
