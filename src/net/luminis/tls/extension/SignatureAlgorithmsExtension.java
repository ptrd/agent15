package net.luminis.tls.extension;

import net.luminis.tls.TlsConstants;

import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.SignatureScheme.*;

// https://tools.ietf.org/html/rfc8446#section-4.2.3:
// "Note: This enum is named "SignatureScheme" because there is already a "SignatureAlgorithm" type in TLS 1.2,
// which this replaces.  We use the term "signature algorithm" throughout the text."
public class SignatureAlgorithmsExtension extends Extension {

    private TlsConstants.SignatureScheme[] algorithms;

    public SignatureAlgorithmsExtension() {
        algorithms = new TlsConstants.SignatureScheme[] {
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
    }

    public SignatureAlgorithmsExtension(TlsConstants.SignatureScheme[] signatureAlgorithms) {
        this.algorithms = signatureAlgorithms;
    }

    @Override
    public byte[] getBytes() {

        int extensionLength = 2 + algorithms.length * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.signature_algorithms.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (algorithms.length * 2));
        for (TlsConstants.SignatureScheme namedGroup: algorithms) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }
}
