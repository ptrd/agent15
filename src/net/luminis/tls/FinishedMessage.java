package net.luminis.tls;

import java.nio.ByteBuffer;

public class FinishedMessage extends TlsMessage {

    private byte[] data;

    public FinishedMessage() {
    }

    public FinishedMessage(TlsState state) {

        byte[] hmac = state.computeHandshakeFinishedHmac();

        int remainingLength = hmac.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + remainingLength);
        buffer.put(TlsConstants.HandshakeType.finished.value);
        // 3 bytes length, first byte will always be 0, as length will never exceed 2^16 (not even 2^8...)
        buffer.put((byte) 0x00);
        buffer.putShort((short) remainingLength);

        buffer.put(hmac);
        data = buffer.array();
    }

    public FinishedMessage parse(ByteBuffer buffer, int length, TlsState state) {
        Logger.debug("Got Finished message (" + length + " bytes)");

        // Update state.
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setServerFinished(raw);

        return this;
    }

    public byte[] getBytes() {
        return data;
    }
}
