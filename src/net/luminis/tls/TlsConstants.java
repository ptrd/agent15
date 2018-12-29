package net.luminis.tls;

public class TlsConstants {


    enum ContentType {
          invalid(0),
          change_cipher_spec(20),
          alert(21),
          handshake(22),
          application_data(23),
        ;

        public final byte value;

        ContentType(int value) {
            this.value = (byte) value;
        }
    } ;


    public enum HandshakeType {
          client_hello(1),
          server_hello(2),
          new_session_ticket(4),
          end_of_early_data(5),
          encrypted_extensions(8),
          certificate(11),
          certificate_request(13),
          certificate_verify(15),
          finished(20),
          key_update(24),
          message_hash(254),
        ;

        public final byte value;

        HandshakeType(int value) {
            this.value = (byte) value;
        }
    };

    enum ExtensionType {
        server_name(0),                             /* RFC 6066 */
        max_fragment_length(1),                     /* RFC 6066 */
        status_request(5),                          /* RFC 6066 */
        supported_groups(10),                       /* RFC 8422, 7919 */
        signature_algorithms(13),                   /* RFC 8446 */
        use_srtp(14),                               /* RFC 5764 */
        heartbeat(15),                              /* RFC 6520 */
        application_layer_protocol_negotiation(16), /* RFC 7301 */
        signed_certificate_timestamp(18),           /* RFC 6962 */
        client_certificate_type(19),                /* RFC 7250 */
        server_certificate_type(20),                /* RFC 7250 */
        padding(21),                                /* RFC 7685 */
        pre_shared_key(41),                         /* RFC 8446 */
        early_data(42),                             /* RFC 8446 */
        supported_versions(43),                     /* RFC 8446 */
        cookie(44),                                 /* RFC 8446 */
        psk_key_exchange_modes(45),                 /* RFC 8446 */
        certificate_authorities(47),                /* RFC 8446 */
        oid_filters(48),                            /* RFC 8446 */
        post_handshake_auth(49),                    /* RFC 8446 */
        signature_algorithms_cert(50),              /* RFC 8446 */
        key_share(51),
        ;

        public final short value;

        ExtensionType(int value) {
            this.value = (short) value;
        }
    }
    
    
    enum NamedGroup {

          /* Elliptic Curve Groups (ECDHE) */
          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
          x25519(0x001D), x448(0x001E),

          /* Finite Field Groups (DHE) */
          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
          ffdhe6144(0x0103), ffdhe8192(0x0104),
        ;

        public short value;

        NamedGroup(int value) {
            this.value = (short) value;
        }
    } ;


     public enum SignatureScheme {
          /* RSASSA-PKCS1-v1_5 algorithms */
          rsa_pkcs1_sha256(0x0401),
          rsa_pkcs1_sha384(0x0501),
          rsa_pkcs1_sha512(0x0601),

          /* ECDSA algorithms */
          ecdsa_secp256r1_sha256(0x0403),
          ecdsa_secp384r1_sha384(0x0503),
          ecdsa_secp521r1_sha512(0x0603),

          /* RSASSA-PSS algorithms with public key OID rsaEncryption */
          rsa_pss_rsae_sha256(0x0804),
          rsa_pss_rsae_sha384(0x0805),
          rsa_pss_rsae_sha512(0x0806),

          /* EdDSA algorithms */
          ed25519(0x0807),
          ed448(0x0808),

          /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
          rsa_pss_pss_sha256(0x0809),
          rsa_pss_pss_sha384(0x080a),
          rsa_pss_pss_sha512(0x080b),

          /* Legacy algorithms */
          rsa_pkcs1_sha1(0x0201),
          ecdsa_sha1(0x0203),
         ;

         public final short value;

         SignatureScheme(int value) {
             this.value = (short) value;
         }
     }


     enum PskKeyExchangeMode {
         psk_ke(0),
         psk_dhe_ke(1);

         public final byte value;

         PskKeyExchangeMode(int value) {
             this.value = (byte) value;
         }
     }


     enum CertificateType {
          X509(0),
          RawPublicKey(2),
         ;

         public final byte value;

         CertificateType(int value) {
             this.value = (byte) value;
         }
     } ;


    // https://tools.ietf.org/html/rfc8446#appendix-B.4  Cipher Suites
    public static byte[] TLS_AES_128_GCM_SHA256 = new byte[]        { 0x13, 0x01};
    public static byte[] TLS_AES_256_GCM_SHA384 = new byte[]        { 0x13, 0x02};
    public static byte[] TLS_CHACHA20_POLY1305_SHA256  = new byte[] { 0x13, 0x03};
    public static byte[] TLS_AES_128_CCM_SHA256 = new byte[]        { 0x13, 0x04};
    public static byte[] TLS_AES_128_CCM_8_SHA256 = new byte[]      { 0x13, 0x05};
}
