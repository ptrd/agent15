package net.luminis.tls;

import net.luminis.tls.extension.*;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;


public class ClientHello extends HandshakeMessage {

    private static final int MAX_CLIENT_HELLO_SIZE = 3000;
    public static final byte[][] SUPPORTED_CIPHERS = new byte[][]{TlsConstants.TLS_AES_128_GCM_SHA256, TlsConstants.TLS_AES_256_GCM_SHA384};

    private static Random random = new Random();
    private static SecureRandom secureRandom = new SecureRandom();
    private final byte[] data;
    private byte[] clientRandom;

    public ClientHello(String serverName, ECPublicKey publicKey) {
        this(serverName, publicKey, true, SUPPORTED_CIPHERS, Collections.emptyList());
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, List<Extension> extraExtensions) {
        this(serverName, publicKey, compatibilityMode, SUPPORTED_CIPHERS, extraExtensions);
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, byte[][] supportedCiphers, List<Extension> extraExtensions) {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_CLIENT_HELLO_SIZE);

        // HandshakeType client_hello(1),
        buffer.put((byte) 1);

        // Reserve 3 bytes for length
        byte[] length = new byte[3];
        buffer.put(length);

        // client version
        buffer.put((byte) 0x03);
        buffer.put((byte) 0x03);

        // client random 32 bytes
        clientRandom = new byte[32];
        secureRandom.nextBytes(clientRandom);
        buffer.put(clientRandom);

        byte[] sessionId;
        if (compatibilityMode) {
            sessionId = new byte[32];
            random.nextBytes(sessionId);
        }
        else {
            sessionId = new byte[0];
        }
        buffer.put((byte) sessionId.length);
        if (sessionId.length > 0)
            buffer.put(sessionId);

        buffer.putShort((short) (supportedCiphers.length * 2));
        for (byte[] cipher: supportedCiphers) {
            buffer.put(cipher);
        }

        // Compression
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        // the "null" compression method in prior versions of TLS. "
        buffer.put(new byte[] {
                (byte) 0x01, (byte) 0x00
        });

        Extension[] defaultExtensions = new Extension[] {
                new ServerNameExtension(serverName),
                new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello),
                new SupportedGroupsExtension(TlsConstants.NamedGroup.secp256r1),
                new SignatureAlgorithmsExtension(),
                new KeyShareExtension(publicKey, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.client_hello),
                new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke)
        };

        List<Extension> extensions = new ArrayList<>();
        extensions.addAll(List.of(defaultExtensions));
        extensions.addAll(extraExtensions);

        int pskExtensionStartPosition = 0;
        ClientHelloPreSharedKeyExtension pskExtension = null;
        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        buffer.putShort((short) extensionsLength);
        for (Extension extension: extensions) {
            if (extension instanceof ClientHelloPreSharedKeyExtension) {
                pskExtension = (ClientHelloPreSharedKeyExtension) extension;
                pskExtensionStartPosition = buffer.position();
            }
            buffer.put(extension.getBytes());
        }

        buffer.limit(buffer.position());
        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short) clientHelloLength);
        
        data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(data);

        if (pskExtension != null) {
            pskExtension.calculateBinder(data, pskExtensionStartPosition);
            buffer.position(pskExtensionStartPosition);
            buffer.put(pskExtension.getBytes());
            buffer.rewind();
            buffer.get(data);
        }
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }
}
