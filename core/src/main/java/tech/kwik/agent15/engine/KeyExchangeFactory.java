/*
 * Copyright © 2026 Peter Doornbosch, Chris Burdess
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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.TlsConstants;

import java.util.List;

/**
 * Creates the key exchange implementation for a given TLS named group.
 * <p>
 * The default {@link tech.kwik.agent15.engine.impl.TlsClientEngineImpl} and
 * {@link tech.kwik.agent15.engine.impl.TlsServerEngineImpl} implementations locate factories with a
 * {@link java.util.ServiceLoader}. Any JAR or module on the application class/module path may register another
 * {@code KeyExchangeFactory} provider; that code runs during the handshake and can affect key agreement for the
 * groups it claims. Only add providers you trust, the same way you would trust code on the classpath. When two
 * providers advertise the same named group, Agent15's {@link tech.kwik.agent15.engine.impl.KeyExchangeFactoryScanner}
 * keeps the bundled core implementation ({@link tech.kwik.agent15.engine.impl.KeyExchangeFactoryImpl}) and ignores
 * the extension for that group.
 */
public interface KeyExchangeFactory {

    KeyExchange forGroup(TlsConstants.NamedGroup group);

    List<TlsConstants.NamedGroup> getSupportedGroups();

    void init();
}
