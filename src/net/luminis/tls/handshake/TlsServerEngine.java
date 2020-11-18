package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;
import net.luminis.tls.TranscriptHash;
import net.luminis.tls.alert.HandshakeFailureAlert;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.extension.*;
import net.luminis.tls.util.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static net.luminis.tls.TlsConstants.NamedGroup.secp256r1;
import static net.luminis.tls.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;

public class TlsServerEngine extends TlsEngine implements ServerMessageProcessor {

    private final ArrayList<TlsConstants.CipherSuite> supportedCiphers;
    private final ArrayList<Extension> extensions;
    private ServerMessageSender serverMessageSender;
    private TlsStatusEventHandler statusHandler;
    private final String ecCurve = "secp256r1";
    private X509Certificate serverCertificate;
    private PrivateKey certificatePrivateKey;
    private TranscriptHash transcriptHash;
    private TlsConstants.CipherSuite selectedCipher;


    public TlsServerEngine(X509Certificate serverCertificate, PrivateKey certificateKey, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        this.serverCertificate = serverCertificate;
        this.certificatePrivateKey = certificateKey;
        this.serverMessageSender = serverMessageSender;
        this.statusHandler = tlsStatusHandler;
        supportedCiphers = new ArrayList<>();
        supportedCiphers.add(TLS_AES_128_GCM_SHA256);
        extensions = new ArrayList<>();
        transcriptHash = new TranscriptHash(32);
    }

    @Override
    public void received(ClientHello clientHello) throws TlsProtocolException, IOException {
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

        // This implementation (yet) only supports secp256r1
        if (!supportedGroupsExt.getNamedGroups().contains(secp256r1)) {
            throw new HandshakeFailureAlert("Failed to negotiate supported group (server only supports secp256r1");
        }

        KeyShareExtension keyShareExtension = (KeyShareExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof KeyShareExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("key share extension is required in Client Hello"));

        KeyShareExtension.KeyShareEntry keyShareEntry = keyShareExtension.getKeyShareEntries().stream()
                .filter(entry -> entry.getNamedGroup() == secp256r1)
                .findFirst()
                .orElseThrow(() -> new IllegalParameterAlert("key share extension group inconsistent with supported groups"));

       SignatureAlgorithmsExtension signatureAlgorithmsExtension = (SignatureAlgorithmsExtension) clientHello.getExtensions().stream()
                .filter(ext -> ext instanceof SignatureAlgorithmsExtension)
                .findFirst()
                .orElseThrow(() -> new MissingExtensionAlert("signature algorithms extension is required in Client Hello"));

       // This implementation (yet) only supports rsa_pss_rsae_sha256 (non compliant, see https://tools.ietf.org/html/rfc8446#section-9.1)
        if (!signatureAlgorithmsExtension.getSignatureAlgorithms().contains(rsa_pss_rsae_sha256)) {
            throw new HandshakeFailureAlert("Failed to negotiate signature algorithm (server only supports rsa_pss_rsae_sha256");
        }

        // So: ClientHello is valid and negotiation was successful, as far as this engine is concerned.
        // Use callback to let context check other prerequisites, for example appropriate ALPN extension
        statusHandler.extensionsReceived(clientHello.getExtensions());

        // Start building TLS state and prepare response
        state = new TlsState(transcriptHash);
        transcriptHash.record(clientHello);

        generateKeys(ecCurve);
        state.setOwnKey(privateKey);
        state.computeEarlyTrafficSecret();
        statusHandler.earlySecretsKnown();

        ServerHello serverHello = new ServerHello(selectedCipher, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, secp256r1, TlsConstants.HandshakeType.server_hello)
        ));
        // Send server hello back to client
        serverMessageSender.send(serverHello);

        // Update state
        transcriptHash.record(serverHello);
        state.setPeerKey(keyShareEntry.getKey());

        // Compute keys
        state.computeSharedSecret();
        state.computeHandshakeSecrets();
        statusHandler.handshakeSecretsKnown();
    }

    @Override
    public void received(FinishedMessage clientFinished) throws TlsProtocolException, IOException {
    }

    public void addSupportedCiphers(List<TlsConstants.CipherSuite> cipherSuites) {
        supportedCiphers.addAll(cipherSuites);
    }

    public void setServerMessageSender(ServerMessageSender serverMessageSender) {
        this.serverMessageSender = serverMessageSender;
    }

    public void setStatusHandler(TlsStatusEventHandler statusHandler) {
        this.statusHandler = statusHandler;
    }

    public TlsConstants.CipherSuite getSelectedCipher() {
        return selectedCipher;
    }

    // TODO: remove this
    public TlsState getState() {
        return state;
    }

}

