/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.extension;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.handshake.EncryptedExtensions;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pkcs1_sha256;

public class EncryptedExtensionsTest {

    @Test
    void parseEmptyEncryptedExtensions() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000002" + "0000");

        EncryptedExtensions ee = new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length);
        assertThat(ee.getExtensions()).isEmpty();
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectMsgLength() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000000" + "00ff");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectExtensionsLength() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000002" + "00ff");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectLengths() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "0000ff" + "00fd");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeEmptyEncryptedExtensions() {
        byte[] data = new EncryptedExtensions().getBytes();

        assertThat(data).isEqualTo(ByteUtils.hexToBytes("08" + "000002" + "0000"));
    }

    @Test
    void serializeEncryptedExtensions() {
        byte[] data = new EncryptedExtensions(List.of(
                new ServerNameExtension("server"),
                new SignatureAlgorithmsExtension(rsa_pkcs1_sha256)
        )).getBytes();

        byte[] expected = ByteUtils.hexToBytes("08" + "000019" + "0017"
                + ByteUtils.bytesToHex(new ServerNameExtension("server").getBytes())
                + ByteUtils.bytesToHex(new SignatureAlgorithmsExtension(rsa_pkcs1_sha256).getBytes()));
        assertThat(data).isEqualTo(expected);
    }

    @Test
    void encryptedExtensionsMustRejectPreSharedKeyExtension() throws Exception {
        // Wire bytes:
        //   msg type 0x08, msg length 0x000008,
        //   extensions list size 0x0006,
        //     pre_shared_key extension (type=0x0029, length=0x0002, selected_identity=0x0000)
        byte[] data = ByteUtils.hexToBytes("08" + "000008" + "0006" + "0029" + "0002" + "0000");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(IllegalParameterAlert.class);
    }
}
