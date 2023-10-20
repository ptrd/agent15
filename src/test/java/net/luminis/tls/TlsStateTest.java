/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.tls;

import at.favre.lib.crypto.HKDF;
import net.luminis.tls.util.ByteUtils;
import net.luminis.tls.util.FieldGetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class TlsStateTest {

    @Test
    void testHdkfExtractUsedByTlsStateForRegression() {
        // Given
        TlsState tlsState = new TlsState(mock(TranscriptHash.class), 16, 32);
        HKDF hkdf = (HKDF) FieldGetter.getField(tlsState, "hkdf");

        // When
        byte[] result = hkdf.extract(new byte[32], ByteUtils.hexToBytes("9dec754406f9f8e7f301ebe9760c8086535470a1bac71f6204131c0dc7510d6f"));

        // Then
        assertThat(result).isEqualTo(ByteUtils.hexToBytes("e3f46a201b376e967810653508d1a41d3b37340221a193188d1fd81f9819ac98"));
    }

    @Test
    void testHdkfExpandUsedByTlsStateForRegression() {
        // Given
        TlsState tlsState = new TlsState(mock(TranscriptHash.class), 16, 32);
        HKDF hkdf = (HKDF) FieldGetter.getField(tlsState, "hkdf");

        // When
        byte[] result = hkdf.expand(ByteUtils.hexToBytes("9dec754406f9f8e7f301ebe9760c8086535470a1bac71f6204131c0dc7510d6f"), "some derivation".getBytes(StandardCharsets.UTF_8), 32);

        // Then
        assertThat(result).isEqualTo(ByteUtils.hexToBytes("0bd79c1626379ee8b7704a25406f03202cb6dff67e6236ce2308711d83539530"));
    }
}