package net.luminis.tls;

import java.nio.ByteBuffer;

public class CertificateVerifyMessage {

    public CertificateVerifyMessage parse(ByteBuffer buffer, int length, TlsState state) {

        Logger.debug("Got Certificate Verify message( " + length + " bytes)");

        // Update state.
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setCertificateVerify(raw);

        return this;
    }
}
