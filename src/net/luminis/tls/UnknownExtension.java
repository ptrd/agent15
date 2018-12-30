package net.luminis.tls;

import java.nio.ByteBuffer;

public class UnknownExtension extends Extension {

    private byte[] data;

    public UnknownExtension parse(ByteBuffer buffer) {
        buffer.mark();
        buffer.getShort();
        int length = buffer.getShort();
        buffer.reset();
        data = new byte[4 + length];
        buffer.get(data);

        return this;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
