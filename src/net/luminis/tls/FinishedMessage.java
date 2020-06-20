package net.luminis.tls;

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

    public FinishedMessage(TlsState state) {
        // Assuming client finished message (client role)

        // The hmac sent in the client finished message does not include itself (of course)
        byte[] hmac = state.computeHandshakeFinishedHmac(false);

        int remainingLength = hmac.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + remainingLength);
        buffer.put(TlsConstants.HandshakeType.finished.value);
        // 3 bytes length, first byte will always be 0, as length will never exceed 2^16 (not even 2^8...)
        buffer.put((byte) 0x00);
        buffer.putShort((short) remainingLength);

        buffer.put(hmac);
        raw = buffer.array();

        // Make the client finished message available for computing the transcript hash
        state.setClientFinished(raw);   // TODO: remove
    }

    @Override
    TlsConstants.HandshakeType getType() {
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
