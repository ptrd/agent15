package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static net.luminis.tls.TlsConstants.*;
import static net.luminis.tls.TlsConstants.HandshakeType.*;

public class HandshakeRecord {

    private byte[] data;
    private List<HandshakeMessage> messages = new ArrayList<>();


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

    public HandshakeRecord parse(PushbackInputStream input, TlsState state, TlsClientEngine tlsClientEngine) throws IOException, TlsProtocolException {
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

        while (buffer.remaining() > 0) {
            HandshakeMessage message = parseHandshakeMessage(buffer, state, tlsClientEngine);
            messages.add(message);
        }

        return this;
    }

    public static HandshakeMessage parseHandshakeMessage(ByteBuffer buffer, TlsState state, TlsClientEngine tlsClientEngine) throws TlsProtocolException {
        buffer.mark();
        int messageType = buffer.get();
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        buffer.reset();

        HandshakeMessage msg;
        if (messageType == server_hello.value) {
            msg = new ServerHello().parse(buffer, length + 4);
            tlsClientEngine.received((ServerHello) msg);
        }
        else if (messageType == encrypted_extensions.value) {
            msg = new EncryptedExtensions().parse(buffer, length + 4, state);
        }
        else if (messageType == certificate.value) {
            msg = new CertificateMessage().parse(buffer, length + 4, state);
        }
        else if (messageType == certificate_verify.value) {
            msg = new CertificateVerifyMessage().parse(buffer, length + 4, state);
        }
        else if (messageType == finished.value) {
            msg = new FinishedMessage().parse(buffer, length + 4, state);
        }
        else if (messageType == new_session_ticket.value) {
            msg = new NewSessionTicketMessage().parse(buffer, length + 4, state);
        }
        else {
            throw new TlsProtocolException("Invalid/unsupported handshake message type (" + messageType + ")");
        }
        return msg;
    }

    public byte[] getBytes() {
        return data;
    }

    public List<HandshakeMessage> getMessages() {
        return messages;
    }
}
