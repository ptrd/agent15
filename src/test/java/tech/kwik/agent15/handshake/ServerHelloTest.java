/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.extension.KeyShareExtension;
import tech.kwik.agent15.extension.SupportedVersionsExtension;
import tech.kwik.agent15.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class ServerHelloTest {

    @Test
    void parseServerHello() throws Exception {
        byte[] data = ByteUtils.hexToBytes("02000077030327303877f58601e5e987b1be085f509adecd10056353daf3843f5f89084a4c6100130100004f002b0002030400330045001700410456517b9551d5ce0950c8210bf1f30b3f5d2b066ac6ac7469d6490387b36d9a57385bdfe2d5d55a1e6956a6d8d771cd7f1aee418b1cf615cbd976ba509a48e9de");

        ServerHello sh = new ServerHello().parse(ByteBuffer.wrap(data), data.length);
        assertThat(sh.getCipherSuite()).isEqualTo(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
    }

    @Test
    void serializeServerHello() throws Exception {
        ServerHello sh = new ServerHello(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
        byte[] serializedData = sh.getBytes();

        int length = 4 + (serializedData[1] << 16) + (serializedData[2] << 8) + serializedData[3];
        assertThat(serializedData.length).isEqualTo(length);

        String expectedInHex = ("02 000028 0303 " + ByteUtils.bytesToHex(sh.getRandom()) + "00 1301 00 0000").replaceAll(" ", "");
        assertThat(serializedData).isEqualTo(ByteUtils.hexToBytes(expectedInHex));
    }

    @Test
    void parsingServerHelloWithIncorrectLegacyVersionShouldThrow() throws Exception {
        byte[] data = ByteUtils.hexToBytes("0200002c03021219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185001301000000");

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseMinimalServerHelloWithMandatoryExtensions() throws Exception {
        String minimalServerHello = addMandatoryExtensions("0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d7425740418500130100");

        byte[] data = ByteUtils.hexToBytes(minimalServerHello);
        ServerHello sh = new ServerHello().parse(ByteBuffer.wrap(data), data.length);

        assertThat(sh.getCipherSuite()).isEqualTo(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
        assertThat(sh.getExtensions())
                .hasSize(2)
                .hasOnlyElementsOfTypes(SupportedVersionsExtension.class, KeyShareExtension.class);
    }

    @Test
    void parseWithTooLargeSessionId() throws Exception {
        String serverHello = addMandatoryExtensions("0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "21" + "d915575532c20dea24fa4b202674f98d742cb206656f2d1590f8c596d96a2a91ad"
                + "130100");

        byte[] data = ByteUtils.hexToBytes(serverHello);

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseWithIllegalSessionIdLength() throws Exception {
        String serverHello = addMandatoryExtensions("0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "ff" + "d915575532c20dea24fa4b202674f98d742cb206656f2d1590f8c596d96a2a91ad"
                + "130100");

        byte[] data = ByteUtils.hexToBytes(serverHello);

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseWithInvalidCipherSuite() throws Exception {
        String serverHelloInHex = addMandatoryExtensions("0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "00" + "1313" + "00");

        byte[] data = ByteUtils.hexToBytes(serverHelloInHex);

        ServerHello serverHello = new ServerHello();
        assertThatCode(() ->
                serverHello.parse(ByteBuffer.wrap(data), data.length))
                .doesNotThrowAnyException();

        assertThat(serverHello.getCipherSuite()).isNull();
    }

    @Test
    void parseWithIllegalLegacyCompressionMethod() throws Exception {
        String serverHello = addMandatoryExtensions("0200002c03031219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "00" + "1301" + "01");

        byte[] data = ByteUtils.hexToBytes(serverHello);

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseServerHelloThatIsTooShort() throws Exception {
        String serverHello = addMandatoryExtensions("0200002c0303" + "1219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "00" + "1301" + "");

        byte[] data = ByteUtils.hexToBytes(serverHello);

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseServerHelloWithMaximumSessionIdThatIsTooShort() throws Exception {
        String serverHello = addMandatoryExtensions("0200002c0303" + "1219785ef730198b9d915575532c20dea24fa42b20b26724f988d74257404185"
                + "20" + "30198b9d915575532c20dea24fa4b202672b2c9b206656f2d1590f8c596d96a2" + "1301" + "");

        byte[] data = ByteUtils.hexToBytes(serverHello);

        assertThatThrownBy(() ->
                new ServerHello().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeServerHelloWithExtension() throws Exception {
        ServerHello sh = new ServerHello(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, List.of(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello)));
        byte[] serializedData = sh.getBytes();

        int length = 4 + (serializedData[1] << 16) + (serializedData[2] << 8) + serializedData[3];
        assertThat(serializedData.length).isEqualTo(length);

        String expectedExtensionBytesInHex = ("0006 002b00020304").replaceAll(" ", "");
        String lastServerHelloBytesInHex = ("00" + "1301" + "00").replaceAll(" ", "");   // session length, cipher, compression
        assertThat(serializedData).endsWith(ByteUtils.hexToBytes(lastServerHelloBytesInHex + expectedExtensionBytesInHex));
    }


    private String addMandatoryExtensions(String shData) {
        //                            length supported versions  key share
        String mandatoryExtensions = "004f   002b00020304        003300450017004104ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e";
        return (shData + mandatoryExtensions).replaceAll(" ", "");
    }
}