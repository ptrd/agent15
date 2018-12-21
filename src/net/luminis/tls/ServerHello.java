package net.luminis.tls;

import java.nio.ByteBuffer;
import java.util.Arrays;

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
            System.out.println("HelloRetryRequest!");
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

        parseExtensions(buffer, length - buffer.position());

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

    private void parseExtensions(ByteBuffer buffer, int length) throws TlsProtocolException {
        int extensionsLength = buffer.getShort();
        if (extensionsLength != length - 2)
            throw new TlsProtocolException("invalid extensions length");

        while (buffer.remaining() > 0) {
            buffer.mark();
            int extensionType = buffer.getShort();
            buffer.reset();

            switch (extensionType) {
                case 51:
                    // key_share(51)
                    parseKeyShareExtension(buffer);
                    break;
                case 43:
                    // supported_versions(43),                     /* RFC 8446 */
                    parseSupportedVersionsExtension(buffer);
                    break;
                case 0:
                    // server_name(0),                             /* RFC 6066 */
                case 1:
                    // max_fragment_length(1),                     /* RFC 6066 */
                case 5:
                       // status_request(5),                          /* RFC 6066 */
                case 10:
                    // supported_groups(10),                       /* RFC 8422, 7919 */
                case 13:
                    // signature_algorithms(13),                   /* RFC 8446 */
                case 14:
                    // use_srtp(14),                               /* RFC 5764 */
                case 15:
                        // heartbeat(15),                              /* RFC 6520 */
                case 16:
                        // application_layer_protocol_negotiation(16), /* RFC 7301 */
                case 18:
                    // signed_certificate_timestamp(18),           /* RFC 6962 */
                case 19:
                    // client_certificate_type(19),                /* RFC 7250 */
                case 20:
                        // server_certificate_type(20),                /* RFC 7250 */
                case 21:
                    // padding(21),                                /* RFC 7685 */
                case 41:
                        // pre_shared_key(41),                         /* RFC 8446 */
                case 42:
                        // early_data(42),                             /* RFC 8446 */
                case 44:
                    // cookie(44),                                 /* RFC 8446 */
                case 45:
                        // psk_key_exchange_modes(45),                 /* RFC 8446 */
                case 47:
                    // certificate_authorities(47),                /* RFC 8446 */
                case 48:
                    // oid_filters(48),                            /* RFC 8446 */
                case 49:
                        // post_handshake_auth(49),                    /* RFC 8446 */
                case 50:
                        // signature_algorithms_cert(50),              /* RFC 8446 */
                default:
                    parseUnknownExtension(buffer);
            }
        }
    }


    private void parseKeyShareExtension(ByteBuffer buffer) throws TlsProtocolException {
        buffer.getShort();
        int length = buffer.getShort();
        int group = buffer.getShort();
        switch (group) {
            case 0x0017:
                keyGroup = "secp256r1";
                break;
            default:
                throw new TlsProtocolException("Unsupported key group " + group);
        }
        int keyLength = buffer.getShort();
        serverSharedKey = new byte[keyLength];
        buffer.get(serverSharedKey);
        System.out.println("Server shared key (" + keyLength + "): " + ByteUtils.bytesToHex(serverSharedKey));
    }

    private void parseSupportedVersionsExtension(ByteBuffer buffer) {
        buffer.getShort();
        int length = buffer.getShort();
        tlsVersion = buffer.getShort();
    }

    private void parseUnknownExtension(ByteBuffer buffer) {
        buffer.getShort();
        int length = buffer.getShort();
        for (int i = 0; i < length; i++)
            buffer.get();
    }
}
