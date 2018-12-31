package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions {

    private List<Extension> extensions;

    public EncryptedExtensions parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {

        Logger.debug("Got Encrypted Extensions message (" + length + " bytes)");

        // Update TLS state: raw bytes are needed for computing the "hello hash".
        byte[] raw = new byte[length];
        buffer.mark();
        buffer.get(raw);
        state.setEncryptedExtensions(raw);
        buffer.reset();

        buffer.position(4);  // Skip message type and 3 bytes length

        extensions = parseExtensions(buffer);

        return this;
    }

    static List<Extension> parseExtensions(ByteBuffer buffer) throws TlsProtocolException {
        List<Extension> extensions = new ArrayList<>();

        int extensionsLength = buffer.getShort();
        if (extensionsLength > 0) {
            int startPosition = buffer.position();

            while (buffer.position() - startPosition < extensionsLength) {
                buffer.mark();
                int extensionType = buffer.getShort();
                buffer.reset();

                if (extensionType == TlsConstants.ExtensionType.key_share.value) {
                    extensions.add(new KeyShareExtension().parse(buffer));
                } else if (extensionType == TlsConstants.ExtensionType.supported_versions.value) {
                    extensions.add(new SupportedVersionsExtension().parse(buffer));
                } else {
                    Logger.debug("Unsupported extension, type is: " + extensionType);
                    extensions.add(new UnknownExtension().parse(buffer));
                }
            }
        }
        return extensions;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }
}
