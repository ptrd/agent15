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

import tech.kwik.agent15.alert.IllegalParameterAlert;

import java.util.Arrays;

/**
 * Base for the RFC 10024 post-quantum/traditional hybrid key exchange
 * groups (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024). Each
 * hybrid group concatenates a classical (EC/XDH) share with an ML-KEM
 * share -- and combines their two computed secrets -- in one fixed order
 * that applies consistently to the client key share, the server key
 * share, and the secret combiner alike. Concrete subclasses just supply
 * the two component KeyExchanges, their fixed lengths, and that one
 * order flag; all the splitting/concatenating/combining is implemented
 * once, here, so the order can't independently drift between the three
 * places it has to agree.
 */
public abstract class HybridKeyExchange implements KeyExchange {

    private final String groupName;
    private final KeyExchange classical;
    private final int classicalShareLength;
    private final KeyExchange pqc;
    private final int pqcClientShareLength;
    private final int pqcServerShareLength;
    private final boolean pqcFirst;

    /**
     * @param groupName             the hybrid group's name, used only in error messages
     * @param classical             the ECDH or XDH component
     * @param classicalShareLength  its fixed share length (identical for client and server)
     * @param pqc                   the ML-KEM component
     * @param pqcClientShareLength  its encapsulation-key length (the client share)
     * @param pqcServerShareLength  its ciphertext length (the server share)
     * @param pqcFirst              true if the ML-KEM component comes first in the
     *                              concatenation/combiner order (X25519MLKEM768); false if the
     *                              classical component comes first (the secp256r1/secp384r1 hybrids)
     */
    protected HybridKeyExchange(String groupName, KeyExchange classical, int classicalShareLength,
            KeyExchange pqc, int pqcClientShareLength, int pqcServerShareLength, boolean pqcFirst) {
        this.groupName = groupName;
        this.classical = classical;
        this.classicalShareLength = classicalShareLength;
        this.pqc = pqc;
        this.pqcClientShareLength = pqcClientShareLength;
        this.pqcServerShareLength = pqcServerShareLength;
        this.pqcFirst = pqcFirst;
    }

    @Override
    public void generateClientKeyPair() {
        classical.generateClientKeyPair();
        pqc.generateClientKeyPair();
    }

    @Override
    public byte[] getClientKeyShare() {
        return combine(classical.getClientKeyShare(), pqc.getClientKeyShare());
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        int expectedLength = classicalShareLength + pqcServerShareLength;
        if (serverKeyShare.length != expectedLength) {
            throw new IllegalParameterAlert("invalid " + groupName + " server key share length: " + serverKeyShare.length);
        }
        byte[] classicalPart = pqcFirst
                ? Arrays.copyOfRange(serverKeyShare, pqcServerShareLength, expectedLength)
                : Arrays.copyOfRange(serverKeyShare, 0, classicalShareLength);
        byte[] pqcPart = pqcFirst
                ? Arrays.copyOfRange(serverKeyShare, 0, pqcServerShareLength)
                : Arrays.copyOfRange(serverKeyShare, classicalShareLength, expectedLength);

        byte[] classicalSecret = classical.clientComputeSharedSecret(classicalPart);
        byte[] pqcSecret = pqc.clientComputeSharedSecret(pqcPart);
        return combine(classicalSecret, pqcSecret);
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
        int expectedLength = classicalShareLength + pqcClientShareLength;
        if (clientKeyShare.length != expectedLength) {
            throw new IllegalParameterAlert("invalid " + groupName + " client key share length: " + clientKeyShare.length);
        }
        byte[] classicalPart = pqcFirst
                ? Arrays.copyOfRange(clientKeyShare, pqcClientShareLength, expectedLength)
                : Arrays.copyOfRange(clientKeyShare, 0, classicalShareLength);
        byte[] pqcPart = pqcFirst
                ? Arrays.copyOfRange(clientKeyShare, 0, pqcClientShareLength)
                : Arrays.copyOfRange(clientKeyShare, classicalShareLength, expectedLength);

        byte[] classicalSecret = classical.serverProcessClientKeyShare(classicalPart);
        byte[] pqcSecret = pqc.serverProcessClientKeyShare(pqcPart);
        return combine(classicalSecret, pqcSecret);
    }

    @Override
    public byte[] getServerKeyShare() {
        return combine(classical.getServerKeyShare(), pqc.getServerKeyShare());
    }

    /**
     * Concatenates the classical and pqc parts in this group's fixed
     * order -- the single place that order is applied, for the client
     * key share, the server key share, and the secret combiner alike.
     */
    private byte[] combine(byte[] classicalPart, byte[] pqcPart) {
        byte[] first = pqcFirst ? pqcPart : classicalPart;
        byte[] second = pqcFirst ? classicalPart : pqcPart;
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
