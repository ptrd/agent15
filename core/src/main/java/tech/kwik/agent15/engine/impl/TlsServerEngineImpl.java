/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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

import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsConstants.SignatureScheme;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.*;
import tech.kwik.agent15.engine.*;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.handshake.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.PskKeyExchangeMode.psk_dhe_ke;

public class TlsServerEngineImpl extends TlsEngineImpl implements TlsServerEngine, ServerMessageProcessor {

    // https://www.rfc-editor.org/rfc/rfc8446.html#appendix-A.2
    enum Status {
        Start,
        ReceivedClientHello,
        SentHelloRetryRequest,
        Negotiated,
        WaitFinished,
        Connected
    }

    private final Set<TlsConstants.CipherSuite> supportedCiphers;
    // The named groups this server is willing to use for key exchange; when empty, all groups the key exchange
    // factory supports are accepted.
    private final Set<TlsConstants.NamedGroup> supportedGroups;
    private final ArrayList<Extension> extensions;
    private final KeyExchangeFactory keyExchangeFactory;
    private ServerMessageSender serverMessageSender;
    protected TlsStatusEventHandler statusHandler;
    private Status status = Status.Start;
    private List<X509Certificate> serverCertificateChain;
    private PrivateKey certificatePrivateKey;
    private TranscriptHash transcriptHash;
    private HelloRetryRequest helloRetryRequest;
    private KeyExchange keyExchange;
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

    /**
     * Create new TLS server engine.
     * Caller must ensure that the preferred signature schemes are compatible with the provided certificate (i.e. that the certificate's public key can be used with all signature schemes).
     * @param certificates  the certificate chain for the server certificate
     * @param certificateKey  the private key for the server certificate
     * @param preferredSignatureSchemes   the signature schemes that the server supports (must be compatible with the provided certificate)
     * @param serverMessageSender  the callback that is used to send messages to the client
     * @param tlsStatusHandler  the callback that is used to notify the context of status changes in the TLS engine, for example when secrets become available or when the handshake is finished
     * @param tlsSessionRegistry  the registry that is used to store and retrieve session data for session resumption; can be null if session resumption is not supported
     * @param keyExchangeFactory  the factory that creates the key exchange for a given named group
     */
    public TlsServerEngineImpl(List<X509Certificate> certificates, PrivateKey certificateKey, List<SignatureScheme> preferredSignatureSchemes,
                               ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler, TlsSessionRegistry tlsSessionRegistry,
                               KeyExchangeFactory keyExchangeFactory) {
        this.serverCertificateChain = certificates;
        this.certificatePrivateKey = certificateKey;
        this.preferredSignatureSchemes = preferredSignatureSchemes;
        this.serverMessageSender = serverMessageSender;
        this.statusHandler = tlsStatusHandler;
        this.keyExchangeFactory = keyExchangeFactory;

        supportedCiphers = new HashSet<>();
        supportedCiphers.add(TLS_AES_128_GCM_SHA256);
        supportedGroups = new HashSet<>();
        extensions = new ArrayList<>();
        serverExtensions = new ArrayList<>();
        clientSupportedKeyExchangeModes = new ArrayList<>();
        sessionRegistry = tlsSessionRegistry;
    }

    @Override
    public void received(ClientHello clientHello, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        if (protectedBy != ProtectionKeysType.None) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.Start && status != Status.SentHelloRetryRequest) {
            throw new UnexpectedMessageAlert("client hello already received");
        }
        boolean isRetriedClientHello = status == Status.SentHelloRetryRequest;
        status = Status.ReceivedClientHello;

        // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
        // "There MUST NOT be more than one extension of the same type in a given extension block."
        HandshakeMessage.checkForDuplicateExtensions(clientHello.getExtensions());

        checkSupportedVersions(clientHello);

        selectedCipher = negotiateCipherSuite(clientHello);
        if (isRetriedClientHello && selectedCipher != helloRetryRequest.getCipherSuite()) {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
            // "Servers MUST ensure that they negotiate the same cipher suite when receiving a conformant updated
            //  ClientHello (if the server selects the cipher suite as the first step in the negotiation, then this
            //  will happen automatically)."
            throw new IllegalParameterAlert("cipher suite does not match the one in the hello retry request");
        }
        if (!isRetriedClientHello) {
            // The cipher suite determines the hash function, so the transcript hash can be created now. When a hello
            // retry request was sent it already exists, and must be kept: it holds the synthetic message that replaces
            // the first client hello, followed by the hello retry request.
            transcriptHash = new TranscriptHash(hashLength(selectedCipher));
        }

        TlsConstants.NamedGroup negotiatedGroup = negotiateNamedGroup(clientHello);

        // Negotiate the signature scheme before deciding on a hello retry request: when negotiation fails the
        // handshake cannot succeed, so there is no point in asking the client to retry first.
        signatureScheme = negotiateSignatureScheme(clientHello);

        KeyShareExtension.KeyShareEntry selectedKeyShareEntry;
        if (isRetriedClientHello) {
            selectedKeyShareEntry = retriedKeyShareEntry(clientHello);
        }
        else {
            Optional<KeyShareExtension.KeyShareEntry> keyShareEntry = selectKeyShareEntry(clientHello);
            if (keyShareEntry.isEmpty()) {
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.1
                // "If the server selects an (EC)DHE group and the client did not offer a compatible "key_share"
                //  extension in the initial ClientHello, the server MUST respond with a HelloRetryRequest
                //  (Section 4.1.4) message."
                sendHelloRetryRequest(clientHello, negotiatedGroup);
                return;
            }
            selectedKeyShareEntry = keyShareEntry.get();
        }
        keyExchange = keyExchangeFactory.forGroup(selectedKeyShareEntry.getNamedGroup());

        collectClientSupportedKeyExchangeModes(clientHello);

        // So: ClientHello is valid and negotiation was successful, as far as this engine is concerned.
        // Use callback to let context check other prerequisites, for example appropriate ALPN extension
        statusHandler.extensionsReceived(clientHello.getExtensions());

        status = Status.Negotiated;

        // Start building TLS state and prepare response. First check whether client wants to use PSK (resumption)
        PskSelection pskSelection = processPreSharedKey(clientHello);

        transcriptHash.record(clientHello);

        state.computeEarlyTrafficSecret();
        statusHandler.earlySecretsKnown();

        sendServerFlight(selectedKeyShareEntry, pskSelection);
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1
     * "Implementations of this specification MUST send this extension in the ClientHello containing all versions of
     *  TLS which they are prepared to negotiate (for this specification, that means minimally 0x0304 (...))."
     */
    private void checkSupportedVersions(ClientHello clientHello) throws ProtocolVersionAlert {
        SupportedVersionsExtension supportedVersionsExt = (SupportedVersionsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SupportedVersionsExtension)
                .findFirst()
                .orElseThrow(() -> new ProtocolVersionAlert("supported versions extension is required in Client Hello"));
        if (!supportedVersionsExt.containsTls13()) {
            throw new ProtocolVersionAlert("client does not support TLS 1.3");
        }
    }

    /**
     * Returns the first cipher suite offered by the client that this server supports.
     */
    private TlsConstants.CipherSuite negotiateCipherSuite(ClientHello clientHello) throws HandshakeFailureAlert {
        return clientHello.getCipherSuites().stream()
                .filter(it -> supportedCiphers.contains(it))
                .findFirst()
                // https://tools.ietf.org/html/rfc8446#section-4.1.1
                // "If the server is unable to negotiate a supported set of parameters (...) it MUST abort the handshake
                // with either a "handshake_failure" or "insufficient_security" fatal alert "
                .orElseThrow(() -> new HandshakeFailureAlert("Failed to negotiate a cipher (server only supports " + supportedCiphers.stream().map(c -> c.toString()).collect(Collectors.joining(", ")) + ")"));
    }

    /**
     * Returns the first group offered by the client that this server is willing to use for key exchange. Note that this
     * says nothing about the key shares the client provided: the client may have offered a group without providing a
     * key share for it, which is exactly the case that calls for a hello retry request.
     */
    private TlsConstants.NamedGroup negotiateNamedGroup(ClientHello clientHello) throws TlsProtocolException {
        return clientSupportedGroups(clientHello).stream()
                .filter(this::isSupportedGroup)
                .findFirst()
                .orElseThrow(() -> new HandshakeFailureAlert("Failed to negotiate supported group"));
    }

    private List<TlsConstants.NamedGroup> clientSupportedGroups(ClientHello clientHello) throws MissingExtensionAlert {
        SupportedGroupsExtension clientSupportedGroups = (SupportedGroupsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SupportedGroupsExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("supported groups extension is required in Client Hello"));
        return clientSupportedGroups.getNamedGroups();
    }

    /**
     * Returns the key share entry this server will use for the key exchange, or empty when the client did not provide
     * a key share for any group this server is willing to use. Key share entries are in the client's order of
     * preference, so the first one this server supports is selected.
     */
    private Optional<KeyShareExtension.KeyShareEntry> selectKeyShareEntry(ClientHello clientHello) throws MissingExtensionAlert {
        return keyShareExtension(clientHello).getKeyShareEntries().stream()
                .filter(entry -> isSupportedGroup(entry.getNamedGroup()))
                .findFirst();
    }

    /**
     * Returns the key share entry of a client hello that is sent in response to a hello retry request. Such a client
     * hello must provide exactly the key share that was asked for.
     */
    private KeyShareExtension.KeyShareEntry retriedKeyShareEntry(ClientHello clientHello) throws TlsProtocolException {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
        // "when sending the new ClientHello, the client MUST replace the original "key_share" extension with one
        //  containing only a new KeyShareEntry for the group indicated in the selected_group field of the triggering
        //  HelloRetryRequest."
        TlsConstants.NamedGroup requestedGroup = helloRetryRequest.getSelectedGroup().orElseThrow();  // Sent HRR always contains group
        List<KeyShareExtension.KeyShareEntry> keyShareEntries = keyShareExtension(clientHello).getKeyShareEntries();
        if (keyShareEntries.size() != 1 || keyShareEntries.get(0).getNamedGroup() != requestedGroup) {
            throw new IllegalParameterAlert("second client hello must contain exactly one key share, for the group of the hello retry request");
        }
        return keyShareEntries.get(0);
    }

    private KeyShareExtension keyShareExtension(ClientHello clientHello) throws MissingExtensionAlert {
        return (KeyShareExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof KeyShareExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("key share extension is required in Client Hello"));
    }

    /**
     * Sends a hello retry request, asking the client to retry with a key share for the given group.
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
     * "The server will send this message in response to a ClientHello message if it is able to find an acceptable set
     *  of parameters but the ClientHello does not contain sufficient information to proceed with the handshake."
     */
    private void sendHelloRetryRequest(ClientHello clientHello, TlsConstants.NamedGroup selectedGroup) throws IOException {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
        // "The server's extensions MUST contain "supported_versions". Additionally, it SHOULD contain the minimal set
        //  of extensions necessary for the client to generate a correct ClientHello pair."
        // No cookie is sent: this server keeps its state between the two client hellos.
        helloRetryRequest = new HelloRetryRequest(selectedCipher, clientHello.getSessionId(),
                List.of(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                        new KeyShareExtension(selectedGroup)));

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
        // "when the server responds to a ClientHello with a HelloRetryRequest, the value of ClientHello1 is replaced
        //  with a special synthetic handshake message of handshake type "message_hash" containing Hash(ClientHello1)"
        transcriptHash.recordHelloRetryRequest(clientHello, helloRetryRequest);

        serverMessageSender.send(helloRetryRequest);

        status = Status.SentHelloRetryRequest;
    }

    private SignatureScheme negotiateSignatureScheme(ClientHello clientHello) throws TlsProtocolException {
        SignatureAlgorithmsExtension signatureAlgorithmsExtension = (SignatureAlgorithmsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SignatureAlgorithmsExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("signature algorithms extension is required in Client Hello"));

        return determineSignatureAlgorithm(signatureAlgorithmsExtension.getSignatureAlgorithms(), preferredSignatureSchemes);
    }

    private void collectClientSupportedKeyExchangeModes(ClientHello clientHello) {
        clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof PskKeyExchangeModesExtension)
                .findFirst()
                .ifPresent(extension -> {
                    clientSupportedKeyExchangeModes.addAll(((PskKeyExchangeModesExtension) extension).getKeyExchangeModes());
                });
    }

    /**
     * Determines whether the session the client wants to resume (if any) is accepted, and creates the transcript hash
     * and the TLS state (with the pre-shared key of the resumed session when resumption is accepted).
     */
    private PskSelection processPreSharedKey(ClientHello clientHello) throws TlsProtocolException {
        assert transcriptHash != null;  // Transcript hash must have been created by now, when cipher suite is negotiated.

        Optional<Extension> pskExtension = clientHello.getExtensions().stream().filter(ext -> ext instanceof ClientHelloPreSharedKeyExtension).findFirst();

        boolean earlyDataAccepted = false;
        Integer selectedIdentity = null;
        if (pskExtension.isPresent()) {
            // "If clients offer "pre_shared_key" without a "psk_key_exchange_modes" extension, servers MUST abort the handshake."
            if (clientSupportedKeyExchangeModes.isEmpty()) {
                throw new MissingExtensionAlert("psk_key_exchange_modes extension required with pre_shared_key");
            }
            // Check for PSK Exchange mode; server only supports psk_dhe_ke
            if (clientSupportedKeyExchangeModes.contains(psk_dhe_ke) && sessionRegistry != null) {
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
                            state = new TlsState(transcriptHash, resumedSession.getPsk(), keyLength(selectedCipher), hashLength(selectedCipher));
                            if (!validateBinder(preSharedKeyExtension.getBinders().get(selectedIdentity), preSharedKeyExtension.getBinderPosition(), clientHello)) {
                                state = null;
                                throw new DecryptErrorAlert("Invalid PSK binder");
                            }
                            // Now PSK is accepted, check for early-data-indication.
                            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
                            // "A client MUST NOT include the "early_data" extension in its followup ClientHello."
                            // "The server then ignores early data ..."
                            if (clientHello.getExtensions().stream().filter(ext -> ext instanceof EarlyDataExtension).findAny().isPresent()
                                    && helloRetryRequest == null) {
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
            state = new TlsState(transcriptHash, keyLength(selectedCipher), hashLength(selectedCipher));
            // The selectedIdentity indicates which PSK was used to resume the session; it must be null when session is not resumed.
            selectedIdentity = null;
        }
        return new PskSelection(selectedIdentity, earlyDataAccepted);
    }

    /**
     * Sends the complete server flight: ServerHello, EncryptedExtensions, (Certificate, CertificateVerify) and
     * Finished.
     */
    private void sendServerFlight(KeyShareExtension.KeyShareEntry selectedKeyShareEntry, PskSelection pskSelection) throws TlsProtocolException, IOException {
        Integer selectedIdentity = pskSelection.selectedIdentity;

        byte[] sharedSecret = keyExchange.serverProcessClientKeyShare(selectedKeyShareEntry.getKeyExchangeData());
        List<Extension> extensions = List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(keyExchange.getServerKeyShare(), selectedKeyShareEntry.getNamedGroup(), TlsConstants.HandshakeType.server_hello));
        if (selectedIdentity != null) {
            extensions = new ArrayList<>(extensions);
            extensions.add(new ServerPreSharedKeyExtension(selectedIdentity.shortValue()));
        }
        ServerHello serverHello = new ServerHello(selectedCipher, extensions);

        // Send server hello back to client
        serverMessageSender.send(serverHello);

        // Update state
        transcriptHash.record(serverHello);

        state.setSharedSecret(sharedSecret);
        state.computeHandshakeSecrets();
        statusHandler.handshakeSecretsKnown();

        if (pskSelection.earlyDataAccepted) {
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

    /**
     * The outcome of processing the pre-shared key extension: the identity of the session that is resumed (null when
     * no session is resumed) and whether early data is accepted.
     */
    private static class PskSelection {

        final Integer selectedIdentity;
        final boolean earlyDataAccepted;

        PskSelection(Integer selectedIdentity, boolean earlyDataAccepted) {
            this.selectedIdentity = selectedIdentity;
            this.earlyDataAccepted = earlyDataAccepted;
        }
    }

    /**
     * Returns whether this server is willing to use the given group for key exchange: it must not be excluded by
     * configuration, and the key exchange factory must be able to provide a key exchange for it.
     */
    private boolean isSupportedGroup(TlsConstants.NamedGroup group) {
        return (supportedGroups.isEmpty() || supportedGroups.contains(group)) && keyExchangeFactory.forGroup(group) != null;
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
            throw new UnexpectedMessageAlert("unexpected finished message");
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
        if (!MessageDigest.isEqual(clientFinished.getVerifyData(), serverHmac)) {
            throw new DecryptErrorAlert("incorrect finished message");
        }

        state.computeResumptionMasterSecret();
        statusHandler.handshakeFinished();

        status = Status.Connected;

        if (sessionRegistry != null && clientSupportedKeyExchangeModes.contains(psk_dhe_ke)) {  // Server only supports psk_dhe_ke
            NewSessionTicketMessage newSessionTicketMessage =
                    sessionRegistry.createNewSessionTicketMessage(currentTicketNumber++, selectedCipher, state, selectedApplicationLayerProtocol, maxEarlyDataSize, additionalSessionData);
            if (newSessionTicketMessage != null) {
                serverMessageSender.send(newSessionTicketMessage);
            }
        }
    }

    protected boolean validateBinder(ClientHelloPreSharedKeyExtension.PskBinderEntry pskBinderEntry, int binderPosition, ClientHello clientHello) {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11, section 4.2.11.2
        byte[] partialCH = Arrays.copyOfRange(clientHello.getBytes(), 0, clientHello.getPskExtensionStartPosition() + binderPosition);
        byte[] binder = state.computePskBinder(partialCH);
        boolean valid = MessageDigest.isEqual(pskBinderEntry.getHmac(), binder);
        return valid;
    }

    @Override
    public void addSupportedCiphers(List<TlsConstants.CipherSuite> cipherSuites) {
        supportedCiphers.addAll(cipherSuites);
    }

    @Override
    public void addSupportedGroups(List<TlsConstants.NamedGroup> namedGroups) {
        supportedGroups.addAll(namedGroups);
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

