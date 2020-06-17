package net.luminis.tls;

import java.nio.ByteBuffer;

public class FinishedMessage extends HandshakeMessage {

    private byte[] data;

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
        data = buffer.array();

        // Make the client finished message available for computing the transcript hash
        state.setClientFinished(data);
    }

    @Override
    TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.finished;
    }

    public FinishedMessage parse(ByteBuffer buffer, int length, TlsState state) {
        Logger.debug("Got Finished message (" + length + " bytes)");

        // Update state.
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setServerFinished(raw);

        return this;
    }

    @Override
    public byte[] getBytes() {
        return data;
    }
}
