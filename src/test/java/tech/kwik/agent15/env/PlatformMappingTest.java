/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.agent15.env;


import tech.kwik.agent15.util.FieldSetter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlatformMappingTest {

    @AfterEach
    void resetPlatform() throws Exception {
        FieldSetter.setField(PlatformMapping.class, PlatformMapping.class.getDeclaredField("currentPlatform"), null);
    }

    @Test
    void defaultMappingIsJDK() {
        // Given

        // When

        // Then
        assertThat(PlatformMapping.algorithmMapping().get("RSASSA-PSS")).isEqualTo("RSASSA-PSS");
    }

    @Test
    void androidMappingHasAlternativeForRSASSA_PSS() {
        // Given

        // When
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android);

        // Then
        assertThat(PlatformMapping.algorithmMapping().get("RSASSA-PSS")).isEqualTo("SHA256withRSA/PSS");
    }

    @Test
    void platformCanOnlyBeSetOnce() {
        // Given
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android);

        // When
        assertThatThrownBy(
                () -> PlatformMapping.usePlatformMapping(PlatformMapping.Platform.JDK)
        )
        // Then
                .isInstanceOf(Exception.class);
    }

    @Test
    void platformCanBeSetWithSameValue() {
        // Given
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android);

        // When
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android);

        // Then
        assertThat(PlatformMapping.algorithmMapping().get("RSASSA-PSS")).isEqualTo("SHA256withRSA/PSS");
    }

}