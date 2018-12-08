package net.luminis.tls;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Random;
import java.util.stream.Stream;

public class ClientHello {

    private static final int MAX_CLIENT_HELLO_SIZE = 3000;

    private static Random random = new Random();
    private static SecureRandom secureRandom = new SecureRandom();
    private final byte[] data;


    public ClientHello(String serverName, ECPublicKey publicKey) {
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
        byte[] clientRandom = new byte[32];
        secureRandom.nextBytes(clientRandom);
        buffer.put(clientRandom);

        byte[] sessionId;
        boolean compatibilityMode = true;
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

        byte[][] supportedCiphers = new byte[][] { TlsConstants.TLS_AES_128_GCM_SHA256, TlsConstants.TLS_AES_256_GCM_SHA384};
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

        Extension[] extensions = new Extension[] {
                new ServerNameExtension(serverName),
                new SupportedVersionsExtension(),
                new SupportedGroupsExtension(),
                new SignatureAlgorithmsExtension(),
                new KeyShareExtension(publicKey, "secp256r1"),
                new PskKeyExchangeModesExtension()
        };

        int extensionsLength = Stream.of(extensions).mapToInt(e -> e.getBytes().length).sum();
        buffer.putShort((short) extensionsLength);
        for (Extension extension: extensions) {
            buffer.put(extension.getBytes());
        }

        buffer.limit(buffer.position());
        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short) clientHelloLength);
        
        data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(data);
    }

    byte[] getBytes() {
        return data;
    }
}
