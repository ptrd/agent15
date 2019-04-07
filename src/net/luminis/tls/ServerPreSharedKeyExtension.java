package net.luminis.tls;

import java.nio.ByteBuffer;

public class ServerPreSharedKeyExtension extends PreSharedKeyExtension {

    public ServerPreSharedKeyExtension() {
    }

    public ServerPreSharedKeyExtension parse(ByteBuffer buffer) {
        // Parsing server variant!
        buffer.getShort();
        int extensionDataLength = buffer.getShort();
        int selectedIdentity = buffer.getShort();
        System.out.println("Server accepts PSK! ");

        return this;
    }


    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
