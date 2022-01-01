/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.extension.*;
import net.luminis.tls.handshake.ClientHello;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientHelloTest {

    @Test
    void parseClientHello() throws Exception {
        //                                      length v1.2 random
        byte[] data = ByteUtils.hexToBytes(("01 000103 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher         comp ext's length
                + "00 0004 1301 1302 0100 00d6"
                // server name extension                version ext    supported groups extension
                + "0000000e000c0000096c6f63616c686f7374 002b0003020304 000a000400020017"
                // signature algorithms extension
                + "000d00140012040308040401050308050501080606010201"
                // key share extension
                + "00330047004500170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
                // psk key exchange modes extension
                + "002d00020101"
                // unknown extension (QUIC transport parameters)
                + "ffa500340032000100048000ea6000040004802625a0000500048003d090000600048003d090000700048003d09000080001010009000101"
                // unknown extension (ec_point_formats)  alpn extension
                + "000b000403000102" +                  "0010000800060568712d3234").replaceAll(" ", ""));
        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);

        assertThat(ch.getClientRandom()).isEqualTo(ByteUtils.hexToBytes("2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"));
        assertThat(ch.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(ServerNameExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(SignatureAlgorithmsExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(KeyShareExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(PskKeyExchangeModesExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(ApplicationLayerProtocolNegotiationExtension.class);
        assertThat(ch.getExtensions()).hasSize(9);
    }

    @Test
    void parseMinimalClientHello() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));
        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);
        assertThat(ch.getClientRandom()).isEqualTo(ByteUtils.hexToBytes("2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"));
        assertThat(ch.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256);
        assertThat(ch.getExtensions()).hasSize(0);
    }

    @Test
    void parseClientHelloWithInvalidLength() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00092b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseClientHelloWithIncorrectClientRamdom() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00092b 0303 2411ec38adb04171"  // 8 bytes instead of 32
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseClientHelloWithInValidCipher() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 130f 0100 0000").replaceAll(" ", ""));

        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);
        assertThat(ch.getCipherSuites()).isEmpty();
    }

    @Test
    void parseClientHelloWithPreSharedKeyExtensionNotAsLast() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0046"
                // pre shared key ext
                + "0029 003b 0016 0010 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
                // version ext
                + "002b0003020304"));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        )
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("last extensio");
    }
}