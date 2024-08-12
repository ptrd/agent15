/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.tls.engine.impl;

import net.luminis.tls.ProtectionKeysType;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsConstants.SignatureScheme;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.DecryptErrorAlert;
import net.luminis.tls.alert.HandshakeFailureAlert;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.alert.UnexpectedMessageAlert;
import net.luminis.tls.engine.*;
import net.luminis.tls.extension.*;
import net.luminis.tls.handshake.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static net.luminis.tls.TlsConstants.NamedGroup.x25519;
import static net.luminis.tls.TlsConstants.PskKeyExchangeMode.psk_dhe_ke;

public class TlsServerEngineImpl extends TlsEngineImpl implements TlsServerEngine, ServerMessageProcessor {

    // https://www.rfc-editor.org/rfc/rfc8446.html#appendix-A.2
    enum Status {
        Start,
        ReceivedClientHello,
        Negotiated,
        WaitFinished,
        Connected
    }

    private final Set<TlsConstants.CipherSuite> supportedCiphers;
    private final ArrayList<Extension> extensions;
    private ServerMessageSender serverMessageSender;
    protected TlsStatusEventHandler statusHandler;
    private Status status = Status.Start;
    private List<X509Certificate> serverCertificateChain;
    private PrivateKey certificatePrivateKey;
    private TranscriptHash transcriptHash;
    private TlsConstants.CipherSuite selectedCipher;
    private SignatureScheme signatureScheme;
    private final List<SignatureScheme> preferredSignatureSchemes;
    private List<Extension> serverExtensions;
    private List<TlsConstants.PskKeyExchangeMode> clientSupportedKeyExchangeModes;
    private TlsSessionRegistry sessionRegistry;
    private byte currentTicketNumber = 0;
    private String selectedApplicationLayerProtocol;
    private Long maxEarlyDataSize = 0xffffffffL;  // Simply use max.
    private byte[] additionalSessionData;
    private Function<ByteBuffer, Boolean> sessionDataVerificationCallback;


    public TlsServerEngineImpl(List<X509Certificate> certificates, PrivateKey certificateKey, List<SignatureScheme> preferredSignatureSchemes, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler, TlsSessionRegistry tlsSessionRegistry) {
        this.serverCertificateChain = certificates;
        this.certificatePrivateKey = certificateKey;
        this.preferredSignatureSchemes = preferredSignatureSchemes;
        this.serverMessageSender = serverMessageSender;
        this.statusHandler = tlsStatusHandler;

        supportedCiphers = new HashSet<>();
        supportedCiphers.add(TLS_AES_128_GCM_SHA256);
        extensions = new ArrayList<>();
        serverExtensions = new ArrayList<>();
        clientSupportedKeyExchangeModes = new ArrayList<>();
        sessionRegistry = tlsSessionRegistry;
    }

    public TlsServerEngineImpl(X509Certificate serverCertificate, PrivateKey certificateKey, List<SignatureScheme> preferredSignatureSchemes, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler, TlsSessionRegistry tlsSessionRegistry) {
        this(List.of(serverCertificate), certificateKey, preferredSignatureSchemes, serverMessageSender, tlsStatusHandler, tlsSessionRegistry);
    }

    @Override
    public void received(ClientHello clientHello, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        if (status != Status.Start) {
            return;
        }
        status = Status.ReceivedClientHello;

        // Find first cipher that server supports
        selectedCipher = clientHello.getCipherSuites().stream()
                .filter(it -> supportedCiphers.contains(it))
                .findFirst()
                // https://tools.ietf.org/html/rfc8446#section-4.1.1
                // "If the server is unable to negotiate a supported set of parameters (...) it MUST abort the handshake
                // with either a "handshake_failure" or "insufficient_security" fatal alert "
                .orElseThrow(() -> new HandshakeFailureAlert("Failed to negotiate a cipher (server only supports " + supportedCiphers.stream().map(c -> c.toString()).collect(Collectors.joining(", ")) + ")"));

        SupportedGroupsExtension supportedGroupsExt = (SupportedGroupsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SupportedGroupsExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("supported groups extension is required in Client Hello"));

        // This implementation (yet) only supports secp256r1 and x25519
        List<TlsConstants.NamedGroup> serverSupportedGroups = List.of(TlsConstants.NamedGroup.secp256r1, x25519);
        if (supportedGroupsExt.getNamedGroups().stream()
                .filter(serverSupportedGroups::contains)
                .findFirst()
                .isEmpty()) {
            throw new HandshakeFailureAlert(String.format("Failed to negotiate supported group (server only supports %s)", serverSupportedGroups));
        }

        KeyShareExtension keyShareExtension = (KeyShareExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof KeyShareExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("key share extension is required in Client Hello"));

        KeyShareExtension.KeyShareEntry keyShareEntry = keyShareExtension.getKeyShareEntries().stream()
                .filter(entry -> serverSupportedGroups.contains(entry.getNamedGroup()))
                .findFirst()
                .orElseThrow(() -> new IllegalParameterAlert("key share named group not supported (and no HelloRetryRequest support)"));

        SignatureAlgorithmsExtension signatureAlgorithmsExtension = (SignatureAlgorithmsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SignatureAlgorithmsExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("signature algorithms extension is required in Client Hello"));

        clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof PskKeyExchangeModesExtension)
                .findFirst()
                .ifPresent(extension -> {
                    clientSupportedKeyExchangeModes.addAll(((PskKeyExchangeModesExtension) extension).getKeyExchangeModes());
                });

        signatureScheme = determineSignatureAlgorithm(signatureAlgorithmsExtension.getSignatureAlgorithms(), preferredSignatureSchemes);

        Optional<Extension> pskExtension = clientHello.getExtensions().stream().filter(ext -> ext instanceof ClientHelloPreSharedKeyExtension).findFirst();

        // So: ClientHello is valid and negotiation was successful, as far as this engine is concerned.
        // Use callback to let context check other prerequisites, for example appropriate ALPN extension
        statusHandler.extensionsReceived(clientHello.getExtensions());

        status = Status.Negotiated;

        // Start building TLS state and prepare response. First check whether client wants to use PSK (resumption)
        boolean earlyDataAccepted = false;
        Integer selectedIdentity = null;
        if (pskExtension.isPresent()) {
            // "If clients offer "pre_shared_key" without a "psk_key_exchange_modes" extension, servers MUST abort the handshake."
            if (clientSupportedKeyExchangeModes.isEmpty()) {
                throw new MissingExtensionAlert("psk_key_exchange_modes extension required with pre_shared_key");
            }
            // Check for PSK Exchange mode; server only supports psk_dhe_ke
            if (clientSupportedKeyExchangeModes.contains(psk_dhe_ke)) {
                ClientHelloPreSharedKeyExtension preSharedKeyExtension = (ClientHelloPreSharedKeyExtension) pskExtension.get();
                selectedIdentity = sessionRegistry.selectIdentity(preSharedKeyExtension.getIdentities(), selectedCipher);
                if (selectedIdentity != null) {
                    if (isAcceptable(sessionRegistry.peekSessionData(preSharedKeyExtension.getIdentities().get(selectedIdentity)))) {
                        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
                        // "Prior to accepting PSK key establishment, the server MUST validate the corresponding binder value.
                        //  If this value is not present or does not validate, the server MUST abort the handshake.
                        //  Servers SHOULD NOT attempt to validate multiple binders; rather, they SHOULD select a single PSK
                        //  and validate solely the binder that corresponds to that PSK."
                        TlsSession resumedSession = sessionRegistry.useSession(preSharedKeyExtension.getIdentities().get(selectedIdentity));
                        if (resumedSession != null) {
                            transcriptHash = new TranscriptHash(hashLength(selectedCipher));
                            state = new TlsState(transcriptHash, resumedSession.getPsk(), keyLength(selectedCipher), hashLength(selectedCipher));
                            if (!validateBinder(preSharedKeyExtension.getBinders().get(selectedIdentity), preSharedKeyExtension.getBinderPosition(), clientHello)) {
                                state = null;
                                throw new DecryptErrorAlert("Invalid PSK binder");
                            }
                            // Now PSK is accepted, check for early-data-indication
                            if (clientHello.getExtensions().stream().filter(ext -> ext instanceof EarlyDataExtension).findAny().isPresent()) {
                                // Client intends to send early data, first check whether application layer protocols match
                                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
                                // "In order to accept early data, the server MUST have accepted a PSK cipher suite and selected
                                //  the first key offered in the client's "pre_shared_key" extension. In addition, it MUST verify that the
                                //   following values are the same as those associated with the selected PSK: (...)
                                //   -  The selected cipher suite
                                //   -  The selected ALPN [RFC7301] protocol, if any"
                                // Check for non-null selectedApplicationLayerProtocol ensures it has been set (possibly to empty string, which is allowed)
                                if (selectedIdentity == 0 && selectedApplicationLayerProtocol != null
                                        && selectedApplicationLayerProtocol.equals(resumedSession.getApplicationLayerProtocol())) {
                                    // From TLS point of view, early data is acceptable, use callback to determine if it will be accepted.
                                    earlyDataAccepted = statusHandler.isEarlyDataAccepted();
                                }
                            }
                        }
                    }
                }
            }
        }
        if (state == null) {
            // Resumption was not requested or not successful; init TLS state without PSK.
            transcriptHash = new TranscriptHash(hashLength(selectedCipher));
            state = new TlsState(transcriptHash, keyLength(selectedCipher), hashLength(selectedCipher));
            // The selectedIdentity indicates which PSK was used to resume the session; it must be null when session is not resumed.
            selectedIdentity = null;
        }
        transcriptHash.record(clientHello);

        generateKeys(keyShareEntry.getNamedGroup());
        state.setOwnKey(privateKey);
        state.computeEarlyTrafficSecret();
        statusHandler.earlySecretsKnown();

        List<Extension> extensions = List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, keyShareEntry.getNamedGroup(), TlsConstants.HandshakeType.server_hello));
        if (selectedIdentity != null) {
            extensions = new ArrayList<>(extensions);
            extensions.add(new ServerPreSharedKeyExtension(selectedIdentity.shortValue()));
        }
        ServerHello serverHello = new ServerHello(selectedCipher, extensions);

        // Send server hello back to client
        serverMessageSender.send(serverHello);

        // Update state
        transcriptHash.record(serverHello);
        state.setPeerKey(keyShareEntry.getKey());

        // Compute keys
        state.computeSharedSecret();
        state.computeHandshakeSecrets();
        statusHandler.handshakeSecretsKnown();

        if (earlyDataAccepted) {
            serverExtensions.add(new EarlyDataExtension());
        }
        EncryptedExtensions encryptedExtensions = new EncryptedExtensions(serverExtensions);
        serverMessageSender.send(encryptedExtensions);
        transcriptHash.record(encryptedExtensions);

        // Only if session is not started with a PSK resumption, send certificate and certificate verify
        if (selectedIdentity == null) {
            CertificateMessage certificate = new CertificateMessage(serverCertificateChain);
            serverMessageSender.send(certificate);
            transcriptHash.recordServer(certificate);

            // "The content that is covered under the signature is the hash output as described in Section 4.4.1, namely:
            //      Transcript-Hash(Handshake Context, Certificate)
            byte[] hash = transcriptHash.getServerHash(TlsConstants.HandshakeType.certificate);

            byte[] signature = computeSignature(hash, certificatePrivateKey, signatureScheme, false);
            CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage(signatureScheme, signature);
            serverMessageSender.send(certificateVerify);
            transcriptHash.recordServer(certificateVerify);
        }

        byte[] hmac = computeFinishedVerifyData(transcriptHash.getServerHash(TlsConstants.HandshakeType.certificate_verify), state.getServerHandshakeTrafficSecret());
        FinishedMessage finished = new FinishedMessage(hmac);
        serverMessageSender.send(finished);
        transcriptHash.recordServer(finished);
        state.computeApplicationSecrets();

        status = Status.WaitFinished;
    }

    protected static SignatureScheme determineSignatureAlgorithm(List<SignatureScheme> clientAlgorithms,
                                                        List<SignatureScheme> serverAlgorithms) throws HandshakeFailureAlert {
        return serverAlgorithms.stream()
                .filter(clientAlgorithms::contains)
                .findFirst()
                .orElseThrow(() -> new HandshakeFailureAlert("Failed to negotiate signature algorithm"));
    }

    private boolean isAcceptable(byte[] sessionData) {
        if (sessionDataVerificationCallback == null || sessionData == null) {
            return true;
        }
        else {
            return sessionDataVerificationCallback.apply(ByteBuffer.wrap(sessionData));
        }
    }

    @Override
    public void received(FinishedMessage clientFinished, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        if (status != Status.WaitFinished) {
            return;
        }
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }

        transcriptHash.recordClient(clientFinished);

        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     +-----------+-------------------------+-----------------------------+
        //     | Client    | ClientHello ... later   | client_handshake_traffic_   |
        //     |           | of server               | secret                      |
        //     |           | Finished/EndOfEarlyData |                             |
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        // "The verify_data value is computed as follows:
        //   verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
        //      * Only included if present."
        byte[] serverHmac = computeFinishedVerifyData(transcriptHash.getServerHash(TlsConstants.HandshakeType.finished), state.getClientHandshakeTrafficSecret());
        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "Recipients of Finished messages MUST verify that the contents are correct and if incorrect MUST terminate the connection with a "decrypt_error" alert."
        if (!Arrays.equals(clientFinished.getVerifyData(), serverHmac)) {
            throw new DecryptErrorAlert("incorrect finished message");
        }

        state.computeResumptionMasterSecret();
        statusHandler.handshakeFinished();

        status = Status.Connected;

        if (sessionRegistry != null && clientSupportedKeyExchangeModes.contains(psk_dhe_ke)) {  // Server only supports psk_dhe_ke
            NewSessionTicketMessage newSessionTicketMessage =
                    sessionRegistry.createNewSessionTicketMessage(currentTicketNumber++, selectedCipher, state, selectedApplicationLayerProtocol, maxEarlyDataSize, additionalSessionData);
            serverMessageSender.send(newSessionTicketMessage);
        }
    }

    protected boolean validateBinder(ClientHelloPreSharedKeyExtension.PskBinderEntry pskBinderEntry, int binderPosition, ClientHello clientHello) {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11, section 4.2.11.2
        byte[] partialCH = Arrays.copyOfRange(clientHello.getBytes(), 0, clientHello.getPskExtensionStartPosition() + binderPosition);
        byte[] binder = state.computePskBinder(partialCH);
        boolean valid = Arrays.equals(pskBinderEntry.getHmac(), binder);
        return valid;
    }

    @Override
    public void addSupportedCiphers(List<TlsConstants.CipherSuite> cipherSuites) {
        supportedCiphers.addAll(cipherSuites);
    }

    @Override
    public void setServerMessageSender(ServerMessageSender serverMessageSender) {
        this.serverMessageSender = serverMessageSender;
    }

    @Override
    public void setStatusHandler(TlsStatusEventHandler statusHandler) {
        this.statusHandler = statusHandler;
    }

    @Override
    public TlsConstants.CipherSuite getSelectedCipher() {
        return selectedCipher;
    }

    @Override
    public List<Extension> getServerExtensions() {
        return serverExtensions;
    }

    @Override
    public void addServerExtensions(Extension extension) {
        serverExtensions.add(extension);
    }

    @Override
    public void setSelectedApplicationLayerProtocol(String applicationProtocol) {
        if (applicationProtocol == null) {
            throw new IllegalArgumentException();
        }
        selectedApplicationLayerProtocol = applicationProtocol;
    }

    /**
     * Set (other layer's) session data for this session. When this session is resumed (with a session ticket),
     * this data will be provided to the session data verification callback, which enables the application layer to
     * accept or deny the session resumption based on the data stored in the session.
     * For example, with QUIC this is used to store the QUIC version in the session data, so when the session is
     * resumed, the QUIC layer can verify the same QUIC version is used.
     * @param additionalSessionData
     */
    @Override
    public void setSessionData(byte[] additionalSessionData) {
        this.additionalSessionData = additionalSessionData;
    }

    /**
     * Set the callback that is called before a session is (successfully) resumed. If there is no data associated with
     * the session, the callback is not called and verification is assumed to be successful, i.e. the session will be
     * resumed.
     * @param callback  the callback that is called with the stored session data; when the callback returns false
     *                  the session will not be resumed.
     */
    @Override
    public void setSessionDataVerificationCallback(Function<ByteBuffer, Boolean> callback) {
        this.sessionDataVerificationCallback = callback;
    }
}

