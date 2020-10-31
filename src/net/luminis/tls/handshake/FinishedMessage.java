package net.luminis.tls.handshake;

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.Logger;
import net.luminis.tls.TlsConstants;

import java.nio.ByteBuffer;

public class FinishedMessage extends HandshakeMessage {

    private byte[] verifyData;
    private byte[] raw;

    public FinishedMessage(byte[] hmac) {
        verifyData = hmac;
        serialize();
    }

    public FinishedMessage() {
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.finished;
    }

    public FinishedMessage parse(ByteBuffer buffer, int length) throws DecodeErrorException {
        Logger.debug("Got Finished message (" + length + " bytes)");
        buffer.mark();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.finished, 4 + 32);
        verifyData = new byte[remainingLength];
        buffer.get(verifyData);

        buffer.reset();
        raw = new byte[length];
        buffer.get(raw);

        return this;
    }

    private void serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(4 + verifyData.length);
        buffer.putInt((TlsConstants.HandshakeType.finished.value << 24) | verifyData.length);
        buffer.put(verifyData);
        raw = buffer.array();
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getVerifyData() {
        return verifyData;
    }
}
