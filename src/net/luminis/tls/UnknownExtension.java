package net.luminis.tls;

import net.luminis.tls.extension.Extension;

import java.nio.ByteBuffer;

public class UnknownExtension extends Extension {

    private byte[] data;
    private int type;

    public UnknownExtension parse(ByteBuffer buffer) throws DecodeErrorException {
        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("Extension must be at least 4 bytes long");
        }

        buffer.mark();
        type = buffer.getShort() & 0xffff;
        int length = buffer.getShort();
        if (buffer.remaining() < length) {
            throw new DecodeErrorException("Invalid extension length");
        }
        buffer.reset();
        data = new byte[4 + length];
        buffer.get(data);

        return this;
    }

    public byte[] getData() {
        return data;
    }

    public int getType() {
        return type;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
