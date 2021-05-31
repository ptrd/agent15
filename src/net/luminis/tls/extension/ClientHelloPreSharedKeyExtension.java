/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
package net.luminis.tls.extension;

import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;
import java.util.Date;


public class ClientHelloPreSharedKeyExtension extends PreSharedKeyExtension {

    private byte[] sessionTicketIdentity;
    private long obfuscatedTicketAge;
    private long ticketAgeAdd;
    private final TlsState tlsState;
    private Date ticketCreationDate;
    private int binderPosition;
    private byte[] binder;

    public ClientHelloPreSharedKeyExtension(TlsState state, NewSessionTicket newSessionTicket) {
        tlsState = state;
        ticketCreationDate = newSessionTicket.getTicketCreationDate();
        ticketAgeAdd = newSessionTicket.getTicketAgeAdd();
        sessionTicketIdentity = newSessionTicket.getSessionTicketIdentity();
        obfuscatedTicketAge = ((new Date().getTime() - ticketCreationDate.getTime()) + ticketAgeAdd) % 0x100000000L;
    }

    @Override
    public byte[] getBytes() {
        //                    all-identities-size + identity-size + identity                      + ticket age + all-binders-size + binder-size + binder
        int extensionLength = 2 +                 + 2 +             sessionTicketIdentity.length + 4          + 2                + 1           + 32;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.pre_shared_key.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (2 + sessionTicketIdentity.length + 4));  // size of PskIdentity identities
        buffer.putShort((short) sessionTicketIdentity.length);            // size of the (single) identity
        buffer.put(sessionTicketIdentity);                                // the identity
        buffer.putInt((int) obfuscatedTicketAge);
        binderPosition = buffer.position();
        buffer.putShort((short) 33);                                       // size of PskBinderEntry binders
        buffer.put((byte) 32);                                             // size of the (single) binder
        if (binder == null) {
            buffer.put(new byte[32]);                                          // placeholder for binder
        }
        else {
            buffer.put(binder);
        }

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
    }

    public void calculateBinder(byte[] clientHello, int pskExtensionStartPosition) {
        int partialHelloSize = pskExtensionStartPosition + binderPosition;
        byte[] partialHello = new byte[partialHelloSize];
        ByteBuffer.wrap(clientHello).get(partialHello);

        binder = tlsState.computePskBinder(partialHello);
    }
}
