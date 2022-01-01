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

import net.luminis.tls.Logger;
import net.luminis.tls.TlsProtocolException;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;


public class AlertRecord {

    public void parse(PushbackInputStream input) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = (input.read() << 8) | input.read();
        if (length != 2)
            throw new TlsProtocolException("Invalid alert length (" + length + ")");

        byte[] data = new byte[length];
        int count = input.read(data);
        while (count != length) {
            count += input.read(data, count, length - count);
        }

        parseAlertMessage(ByteBuffer.wrap(data));
    }

    public static void parseAlertMessage(ByteBuffer buffer) throws TlsProtocolException {
        int alertLevel = buffer.get();
        int alertDescription = buffer.get();
        if (alertLevel == 2 && alertDescription == 40) {
            Logger.debug("AlertRecord fatal/handshake_failure");
        }
        else {
            Logger.debug("AlertRecord " + alertLevel + "/" + alertDescription);
        }
    }
}
