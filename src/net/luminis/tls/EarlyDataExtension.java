package net.luminis.tls;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.2.10
public class EarlyDataExtension extends Extension {

    private Long maxEarlyDataSize;

    public Extension parse(ByteBuffer buffer) {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.early_data.value) {
            throw new RuntimeException();  // Must be programming error
        }

        int extensionLength = buffer.getShort();
        // Only when used in New Session Ticket (message), the EarlyDataIndication value is non-empty.
        if (extensionLength == 4) {
            maxEarlyDataSize = buffer.getInt() & 0xffffffffL;
        }

        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public long getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }
}
