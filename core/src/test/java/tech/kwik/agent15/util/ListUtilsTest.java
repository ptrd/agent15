/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.agent15.util;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ListUtilsTest {

    @Test
    void emptyListIsSubSequenceOfAnything() {
        assertThat(ListUtils.isSubSequence(Collections.emptyList(), List.of("a", "b"))).isTrue();
        assertThat(ListUtils.isSubSequence(Collections.emptyList(), Collections.emptyList())).isTrue();
    }

    @Test
    void elementsInTheSameOrderFormASubSequence() {
        assertThat(ListUtils.isSubSequence(List.of("a", "c"), List.of("a", "b", "c"))).isTrue();
        assertThat(ListUtils.isSubSequence(List.of("a", "b", "c"), List.of("a", "b", "c"))).isTrue();
        assertThat(ListUtils.isSubSequence(List.of("c"), List.of("a", "b", "c"))).isTrue();
    }

    @Test
    void elementsInAnotherOrderDoNotFormASubSequence() {
        assertThat(ListUtils.isSubSequence(List.of("c", "a"), List.of("a", "b", "c"))).isFalse();
        assertThat(ListUtils.isSubSequence(List.of("b", "a"), List.of("a", "b", "c"))).isFalse();
    }

    @Test
    void elementThatIsNotInTheSequenceMakesItNoSubSequence() {
        assertThat(ListUtils.isSubSequence(List.of("a", "d"), List.of("a", "b", "c"))).isFalse();
        assertThat(ListUtils.isSubSequence(List.of("d"), List.of("a", "b", "c"))).isFalse();
        assertThat(ListUtils.isSubSequence(List.of("a"), Collections.emptyList())).isFalse();
    }

    @Test
    void repeatedElementNeedsToOccurAsOftenInTheSequence() {
        assertThat(ListUtils.isSubSequence(List.of("a", "a"), List.of("a", "b", "c"))).isFalse();
        assertThat(ListUtils.isSubSequence(List.of("a", "a"), List.of("a", "b", "a"))).isTrue();
    }
}
