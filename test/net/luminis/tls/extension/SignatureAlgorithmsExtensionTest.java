package net.luminis.tls.extension;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.DecodeErrorException;
import net.luminis.tls.TlsConstants;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class SignatureAlgorithmsExtensionTest {

    @Test
    void testParseMultipleAlgorithms() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d00140012040308040401050308050501080606010201"));

        SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension(buffer);

        assertThat(signatureAlgorithmsExtension.getSignatureAlgorithms())
                .containsExactly(TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256,
                        TlsConstants.SignatureScheme.rsa_pss_rsae_sha256,
                        TlsConstants.SignatureScheme.rsa_pkcs1_sha256,
                        TlsConstants.SignatureScheme.ecdsa_secp384r1_sha384,
                        TlsConstants.SignatureScheme.rsa_pss_rsae_sha384,
                        TlsConstants.SignatureScheme.rsa_pkcs1_sha384,
                        TlsConstants.SignatureScheme.rsa_pss_rsae_sha512,
                        TlsConstants.SignatureScheme.rsa_pkcs1_sha512,
                        TlsConstants.SignatureScheme.rsa_pkcs1_sha1
                        );
    }

    @Test
    void testSerializeSingleAlgorithm() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SignatureAlgorithmsExtension(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256).getBytes());

        SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension(buffer);

        assertThat(signatureAlgorithmsExtension.getSignatureAlgorithms()).contains(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256);
    }

    @Test
    void testSerializeMultipleAlgorithm() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SignatureAlgorithmsExtension(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256).getBytes());

        SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension(buffer);

        assertThat(signatureAlgorithmsExtension.getSignatureAlgorithms()).containsExactly(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d00"));

        assertThatThrownBy(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }


    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d0014001204030804040105030805050108"));

        assertThatThrownBy(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInconsistentLengthsThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d00080004040308040401"));

        assertThatThrownBy(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);

    }

    @Test
    void parsingDataWithInvalidAlgorithmsLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d00070005030308040401"));

        assertThatThrownBy(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);

    }

    @Test
    void parsingDataWithInvalidAlgorithmThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d00080006040308040909"));

        assertThatThrownBy(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

}