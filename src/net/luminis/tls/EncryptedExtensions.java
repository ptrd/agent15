package net.luminis.tls;

import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions extends HandshakeMessage {

    private List<Extension> extensions;

    public EncryptedExtensions parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {

        Logger.debug("Got Encrypted Extensions message (" + length + " bytes)");

        // Update TLS state: raw bytes are needed for computing the "hello hash".
        byte[] raw = new byte[length];
        buffer.mark();
        buffer.get(raw);
        state.setEncryptedExtensions(raw);
        buffer.reset();

        buffer.getInt();  // Skip message type and 3 bytes length

        extensions = parseExtensions(buffer, TlsConstants.HandshakeType.server_hello);

        return this;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
