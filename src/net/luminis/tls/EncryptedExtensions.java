package net.luminis.tls;

import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

// https://tools.ietf.org/html/rfc8446#section-4.3.1
public class EncryptedExtensions extends HandshakeMessage {

    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2;

    private List<Extension> extensions;
    private byte[] raw;

    public EncryptedExtensions() {
        extensions = Collections.emptyList();
        serialize();
    }

    public EncryptedExtensions(List<Extension> extensions) {
        this.extensions = extensions;
        serialize();
    }

    @Override
    TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.encrypted_extensions;
    }

    private void serialize() {
        List<byte[]> extensionBytes = extensions.stream().map(extension -> extension.getBytes()).collect(Collectors.toList());
        int extensionsSize = extensionBytes.stream().mapToInt(data -> data.length).sum();

        raw = new byte[1 + 3 + 2 + extensionsSize];
        ByteBuffer buffer = ByteBuffer.wrap(raw);
        buffer.putInt(0x08000000 | (2 + extensionsSize));
        buffer.putShort((short) extensionsSize);
        extensionBytes.forEach(bytes -> buffer.put(bytes));
    }

    public EncryptedExtensions parse(ByteBuffer buffer, int length) throws TlsProtocolException {
        if (buffer.remaining() < MINIMAL_MESSAGE_LENGTH) {
            throw new DecodeErrorException("Message too short");
        }

        buffer.mark();
        int msgLength = buffer.getInt() & 0x00ffffff;
        if (buffer.remaining() < msgLength || msgLength < 2) {
            throw new DecodeErrorException("Incorrect message length");
        }

        extensions = parseExtensions(buffer, TlsConstants.HandshakeType.server_hello);

        // Raw bytes are needed for computing the transcript hash
        buffer.reset();
        raw = new byte[length];
        buffer.mark();
        buffer.get(raw);

        return this;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }
}
