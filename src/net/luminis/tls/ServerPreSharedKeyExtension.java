package net.luminis.tls;

import java.nio.ByteBuffer;

public class ServerPreSharedKeyExtension extends PreSharedKeyExtension {

    private int selectedIdentity;

    public ServerPreSharedKeyExtension() {
    }

    public ServerPreSharedKeyExtension parse(ByteBuffer buffer) {
        // Parsing server variant!
        buffer.getShort();
        int extensionDataLength = buffer.getShort();
        selectedIdentity = buffer.getShort();

        return this;
    }


    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public int getSelectedIdentity() {
        return selectedIdentity;
    }
}
