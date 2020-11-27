package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;
import net.luminis.tls.TranscriptHash;
import net.luminis.tls.alert.DecryptErrorAlert;
import net.luminis.tls.alert.HandshakeFailureAlert;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.extension.*;
import net.luminis.tls.util.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static net.luminis.tls.TlsConstants.NamedGroup.secp256r1;
import static net.luminis.tls.TlsConstants.NamedGroup.x25519;
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
    private List<Extension> serverExtensions;


    public TlsServerEngine(X509Certificate serverCertificate, PrivateKey certificateKey, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        this.serverCertificate = serverCertificate;
        this.certificatePrivateKey = certificateKey;
        this.serverMessageSender = serverMessageSender;
        this.statusHandler = tlsStatusHandler;
        supportedCiphers = new ArrayList<>();
        supportedCiphers.add(TLS_AES_128_GCM_SHA256);
        extensions = new ArrayList<>();
        serverExtensions = new ArrayList<>();
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
                .orElseThrow(() -> new IllegalParameterAlert("key share named group no supported (and no HelloRetryRequest support)"));

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

        generateKeys(keyShareEntry.getNamedGroup());
        state.setOwnKey(privateKey);
        state.computeEarlyTrafficSecret();
        statusHandler.earlySecretsKnown();

        ServerHello serverHello = new ServerHello(selectedCipher, List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(publicKey, keyShareEntry.getNamedGroup(), TlsConstants.HandshakeType.server_hello)
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

        EncryptedExtensions encryptedExtensions = new EncryptedExtensions(serverExtensions);
        serverMessageSender.send(encryptedExtensions);
        transcriptHash.record(encryptedExtensions);

        CertificateMessage certificate = new CertificateMessage(serverCertificate);
        serverMessageSender.send(certificate);
        transcriptHash.record(certificate);

        byte[] signature = computeSignature();
        CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage(rsa_pss_rsae_sha256, signature);
        serverMessageSender.send(certificateVerify);
        transcriptHash.record(certificateVerify);

        byte[] hmac = computeFinishedVerifyData(transcriptHash.getHash(TlsConstants.HandshakeType.certificate_verify), state.getServerHandshakeTrafficSecret());
        FinishedMessage finished = new FinishedMessage(hmac);
        serverMessageSender.send(finished);
        transcriptHash.recordServer(finished);
        state.computeApplicationSecrets();
    }

    @Override
    public void received(FinishedMessage clientFinished) throws TlsProtocolException, IOException {
        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     +-----------+-------------------------+-----------------------------+
        //     | Client    | ClientHello ... later   | client_handshake_traffic_   |
        //     |           | of server               | secret                      |
        //     |           | Finished/EndOfEarlyData |                             |

        byte[] serverHmac = computeFinishedVerifyData(transcriptHash.getServerHash(TlsConstants.HandshakeType.finished), state.getClientHandshakeTrafficSecret());
        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "Recipients of Finished messages MUST verify that the contents are correct and if incorrect MUST terminate the connection with a "decrypt_error" alert."
        if (!Arrays.equals(clientFinished.getVerifyData(), serverHmac)) {
            throw new DecryptErrorAlert("incorrect finished message");
        }
        else {
            statusHandler.handshakeFinished();
        }
    }

    private byte[] computeSignature() {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3
        // "For example, if the transcript hash was 32 bytes of 01 (this length would make sense for SHA-256),
        // the content covered by the digital signature for a server CertificateVerify would be:"

        // "The content that is covered under the signature is the hash output as described in Section 4.4.1, namely:
        //      Transcript-Hash(Handshake Context, Certificate)
        byte[] hash = transcriptHash.getHash(TlsConstants.HandshakeType.certificate);

        //   The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteArrayOutputStream signatureInput = new ByteArrayOutputStream();
        try {
            signatureInput.write(new String(new byte[] { 0x20 }).repeat(64).getBytes(StandardCharsets.US_ASCII));
            signatureInput.write("TLS 1.3, server CertificateVerify".getBytes(StandardCharsets.US_ASCII));
            signatureInput.write(0x00);
            signatureInput.write(hash);
        } catch (IOException e) {
            // Impossible
            throw new RuntimeException();
        }

        try {
            Signature signatureAlgorithm = Signature.getInstance("RSASSA-PSS");
            signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
            signatureAlgorithm.initSign(certificatePrivateKey);
            signatureAlgorithm.update(signatureInput.toByteArray());
            byte[] digitalSignature = signatureAlgorithm.sign();
            return digitalSignature;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + "RSASSA-PSS" + " support");
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            // Impossible
            throw new RuntimeException();
        } catch (SignatureException e) {
            throw new RuntimeException();
        }
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

    public List<Extension> getServerExtensions() {
        return serverExtensions;
    }

    // TODO: remove this
    public TlsState getState() {
        return state;
    }

    public void addServerExtensions(Extension extension) {
        serverExtensions.add(extension);
    }
}

