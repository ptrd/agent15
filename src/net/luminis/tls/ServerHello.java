package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServerHello {

    static byte[] HelloRetryRequest_SHA256 = new byte[] {
            (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A, (byte) 0x61, (byte) 0x11,
            (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91,
            (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
            (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, (byte) 0x33, (byte) 0x9C
    };

    private byte[] raw;
    private byte[] random;
    private String cipherSuite;
    private String keyGroup;
    private byte[] serverSharedKey;
    private short tlsVersion;

    public ServerHello parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {
        buffer.position(4);  // Skip message type and 3 bytes length

        int versionHigh = buffer.get();
        int versionLow = buffer.get();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");

        random = new byte[32];
        buffer.get(random);
        if (Arrays.equals(random, HelloRetryRequest_SHA256)) {
            Logger.debug("HelloRetryRequest!");
        }

        int sessionIdLength = buffer.get();
        byte[] legacySessionIdEcho = new byte[sessionIdLength];
        buffer.get(legacySessionIdEcho);   // TODO: must match, see 4.1.3

        int cipherSuiteCode = buffer.getShort();
        switch (cipherSuiteCode) {
            case 0x1301:
                cipherSuite = "TLS_AES_128_GCM_SHA256";
                break;
            case 0x1302:
                cipherSuite = "TLS_AES_256_GCM_SHA384";
                break;
            case 0x1303:
                cipherSuite = "TLS_CHACHA20_POLY1305_SHA256";
                break;
            case 0x1304:
                cipherSuite = "TLS_AES_128_CCM_SHA256";
                break;
            case 0x1305:
                cipherSuite = "TLS_AES_128_CCM_8_SHA256";
                break;
            default:
                throw new TlsProtocolException("Unknown cipher suite (" + cipherSuiteCode + ")");
        }

        int legacyCompressionMethod = buffer.get();  // TODO: must match, see 4.1.3

        List<Extension> extensions = EncryptedExtensions.parseExtensions(buffer);

        extensions.stream().forEach( extension -> {
            if (extension instanceof KeyShareExtension) {
                serverSharedKey = ((KeyShareExtension) extension).getServerSharedKey();
            }
            else if (extension instanceof SupportedVersionsExtension) {
                tlsVersion = ((SupportedVersionsExtension) extension).getTlsVersion();
            }
        });

        // Post processing after record is completely parsed
        if (tlsVersion != 0x0304) {
            throw new TlsProtocolException("Invalid TLS version");
        }

        // Update state.
        raw = new byte[length];
        buffer.rewind();
        buffer.get(raw);
        state.setServerSharedKey(raw, serverSharedKey);

        return this;
    }
}
