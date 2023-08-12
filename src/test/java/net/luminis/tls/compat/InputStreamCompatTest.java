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
package net.luminis.tls.compat;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


class InputStreamCompatTest {

    @Test
    void resultOfCopyHasSameLengthAsInput() throws Exception {
        // Given
        InputStream input = new ByteArrayInputStream("Hello world".getBytes(StandardCharsets.UTF_8));

        // When
        byte[] result = InputStreamCompat.readAllBytes(input);

        // Then
        assertThat(result.length).isEqualTo(11);
        assertThat(new String(result)).isEqualTo("Hello world");
    }

    @Test
    void copyingEmptyStreamReturnsEmptyArray() throws Exception {
        // Given
        InputStream input = new ByteArrayInputStream(new byte[0]);

        // When
        byte[] result = InputStreamCompat.readAllBytes(input);

        // Then
        assertThat(result.length).isEqualTo(0);
    }

    @Test
    void copyingMoreBytesThanBufferSizeWorks() throws Exception {
        // Given
        InputStream input = new ByteArrayInputStream(new byte[8192 + 1]);

        // When
        byte[] result = InputStreamCompat.readAllBytes(input);

        // Then
        assertThat(result.length).isEqualTo(8193);
    }
}