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
package net.luminis.tls.extension;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class PskKeyExchangeModesExtensionTest {

    @Test
    void testParseSinglePskMode() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d00020101"));

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes()).containsExactly(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testParseMultiplePskModes() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d0003020001"));

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes())
                .containsExactlyInAnyOrder(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testSerializeSinglePskMode() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke).getBytes());

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes()).containsExactly(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }

    @Test
    void testSerializeMultiplePskModes() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke).getBytes());

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes())
                .containsExactlyInAnyOrder(TlsConstants.PskKeyExchangeMode.psk_dhe_ke, TlsConstants.PskKeyExchangeMode.psk_ke);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d000201"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInvalidDataLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d000201"));

        assertThatThrownBy(
                () -> new PskKeyExchangeModesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void unknownCodePointForModeShouldBeIgnored() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002d0003020201"));

        PskKeyExchangeModesExtension pskKeyExchangeModesExtension = new PskKeyExchangeModesExtension(buffer);

        assertThat(pskKeyExchangeModesExtension.getKeyExchangeModes())
                .containsExactlyInAnyOrder(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
    }
}