package net.luminis.tls;

import java.nio.ByteBuffer;

public class CertificateVerifyMessage extends HandshakeMessage {

    public CertificateVerifyMessage parse(ByteBuffer buffer, int length, TlsState state) {

        Logger.debug("Got Certificate Verify message( " + length + " bytes)");

        // Update state.
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setCertificateVerify(raw);

        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
