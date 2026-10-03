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
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.engine.KeyExchangeFactory;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;

import java.util.Map;
import java.util.function.ToIntFunction;

/**
 * Registration rules shared by {@link KeyExchangeFactoryScanner} and {@link SignatureAlgorithmFactoryScanner}.
 */
final class HandshakeFactoryRegistration {

    private static final int CORE_FACTORY_PRIORITY = 1;
    private static final int EXTENSION_FACTORY_PRIORITY = 0;

    private HandshakeFactoryRegistration() {
    }

    static int priority(SignatureAlgorithmFactory factory) {
        // Exact-class check, not instanceof: a ServiceLoader-registered subclass of the core implementation must
        // not inherit core priority, or it could shadow the real core implementation for a scheme it doesn't
        // actually come from.
        return factory.getClass() == SignatureAlgorithmFactoryImpl.class ? CORE_FACTORY_PRIORITY : EXTENSION_FACTORY_PRIORITY;
    }

    static int priority(KeyExchangeFactory factory) {
        return factory.getClass() == KeyExchangeFactoryImpl.class ? CORE_FACTORY_PRIORITY : EXTENSION_FACTORY_PRIORITY;
    }

    static <K, F> void putIfHigherPriority(Map<K, F> map, K key, F factory, int priority, ToIntFunction<F> priorityOf) {
        F existing = map.get(key);
        if (existing == null || priority > priorityOf.applyAsInt(existing)) {
            map.put(key, factory);
        }
    }
}
