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
 * Creates the signature algorithm implementation for a given TLS signature scheme.
 * <p>
 * The default {@link tech.kwik.agent15.engine.impl.TlsClientEngineImpl} and
 * {@link tech.kwik.agent15.engine.impl.TlsServerEngineImpl} implementations locate factories with a
 * {@link java.util.ServiceLoader}. Any JAR or module on the application class/module path may register another
 * {@code SignatureAlgorithmFactory} provider; that code runs during the handshake and can affect signing and
 * certificate verification for the schemes it claims. Only add providers you trust, the same way you would trust
 * code on the classpath. When two providers advertise the same signature scheme, Agent15's
 * {@link tech.kwik.agent15.engine.impl.SignatureAlgorithmFactoryScanner} keeps the bundled core implementation
 * ({@link tech.kwik.agent15.engine.impl.SignatureAlgorithmFactoryImpl}) and ignores the extension for that scheme.
 */
public interface SignatureAlgorithmFactory {

    /**
     * Creates a signature algorithm for the given signature scheme.
     * @param signatureScheme
     * @return  the signature algorithm, or null when this factory does not support the given scheme
     */
    SignatureAlgorithm forSignatureScheme(TlsConstants.SignatureScheme signatureScheme);

    /**
     * Returns the signature schemes this factory can create a signature algorithm for; exactly for these schemes
     * {@link #forSignatureScheme} returns a non-null value.
     * @return
     */
    List<TlsConstants.SignatureScheme> getSupportedSignatureSchemes();

    /**
     * Performs any one-time initialization this factory's signature algorithms need (e.g. warming up a lazily
     * derived value), so that cost is paid here rather than during a handshake. Optional to call; implementations
     * that need no warm-up may leave this empty.
     */
    void init();
}
