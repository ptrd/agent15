/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15;

public interface BinderCalculator {

    /**
     * Computes the binder for a client hello that is the first message of the handshake.
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2
     * "if the client sends ClientHello1, its binder will be computed over: Transcript-Hash(Truncate(ClientHello1))"
     * @param partialClientHello  the client hello up to (not including) the binders list
     */
    default byte[] computePskBinder(byte[] partialClientHello) {
        return computePskBinder(new byte[0], partialClientHello);
    }

    /**
     * Computes the binder for a client hello that is preceded by other handshake messages.
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2
     * "If the server responds with a HelloRetryRequest and the client then sends ClientHello2, its binder will be
     *  computed over: Transcript-Hash(ClientHello1, HelloRetryRequest, Truncate(ClientHello2))"
     * @param transcriptPrefix    the transcript that precedes the client hello (empty for a first client hello); for a
     *                            second client hello, this is the synthetic message that replaces the first client
     *                            hello followed by the hello retry request
     * @param partialClientHello  the client hello up to (not including) the binders list
     */
    byte[] computePskBinder(byte[] transcriptPrefix, byte[] partialClientHello);
}
