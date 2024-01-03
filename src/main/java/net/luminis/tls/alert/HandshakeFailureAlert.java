/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

/**
 * https://tools.ietf.org/html/rfc8446#section-6.2
 * "handshake_failure:  Receipt of a "handshake_failure" alert message
 *       indicates that the sender was unable to negotiate an acceptable
 *       set of security parameters given the options available."
 */
public class HandshakeFailureAlert extends ErrorAlert {

    public HandshakeFailureAlert(String message) {
        super(message, TlsConstants.AlertDescription.handshake_failure);
    }
}

