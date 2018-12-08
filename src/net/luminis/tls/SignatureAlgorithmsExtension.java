package net.luminis.tls;

import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.SignatureScheme.*;

// https://tools.ietf.org/html/rfc8446#section-4.2.3
public class SignatureAlgorithmsExtension extends Extension {

    @Override
    byte[] getBytes() {
        TlsConstants.SignatureScheme[] schemas = new TlsConstants.SignatureScheme[] {
                ecdsa_secp256r1_sha256,
                rsa_pss_rsae_sha256,
                rsa_pkcs1_sha256,
                ecdsa_secp384r1_sha384,
                rsa_pss_rsae_sha384,
                rsa_pkcs1_sha384,
                rsa_pss_rsae_sha512,
                rsa_pkcs1_sha512,
                rsa_pkcs1_sha1
        };

        int extensionLength = 2 + schemas.length * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.signature_algorithms.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (schemas.length * 2));
        for (TlsConstants.SignatureScheme namedGroup: schemas) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }
}
