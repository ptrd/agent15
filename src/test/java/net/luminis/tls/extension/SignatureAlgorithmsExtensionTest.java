/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.tls.extension;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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
    void parsingDataWithUnknownAlgorithmShouldNotFail()  {
        // Wolfssl sends 0x0301 as signature algorithm, which is not defined as a valid signature value in the TLS 1.3 specification.
        // On the contrary: "Some legacy pairs are left unallocated. These algorithms are deprecated as of TLS 1.3.
        //                   They MUST NOT be offered or negotiated by any implementation.  In particular, MD5 [SLOTH],
        //                   SHA-224, and DSA MUST NOT be used."
        // (0x0301 is SHA-224-RSA)
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000d 0016 0014 040308040401050308050501080606010201 0301".replace(" ", "")));

        assertThatCode(
                () -> new SignatureAlgorithmsExtension(buffer)
        ).doesNotThrowAnyException();
    }
}