/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import java.util.List;
import java.util.stream.Collectors;

public class NoApplicationProtocolAlert extends ErrorAlert
{
    public NoApplicationProtocolAlert() {
        super("unsupported application protocol", TlsConstants.AlertDescription.no_application_protocol);
    }

    public NoApplicationProtocolAlert(List<String> requestedProtocols) {
        super("unsupported application protocol: " + requestedProtocols.stream().collect(Collectors.joining(",")),
                TlsConstants.AlertDescription.no_application_protocol);
    }
}
