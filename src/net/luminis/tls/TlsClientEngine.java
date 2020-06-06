package net.luminis.tls;

import net.luminis.tls.exception.MissingExtensionAlert;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;


public class TlsClientEngine implements TrafficSecrets {

    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");
    private List<TlsConstants.SignatureScheme> supportedSignatures = List.of(rsa_pss_rsae_sha256);
    private X509Certificate serverCertificate;

    enum Status {
        Initial,
        ClientHelloSent,
        ServerHelloReceived,
        EncryptedExtensionsReceived,
        CertificateReceived,
        CertificateVerifyReceived,
    }

    private final ClientMessageSender sender;
    private String serverName;
    private String ecCurve = "secp256r1";
    private ECPublicKey publicKey;
    private ECPrivateKey privateKey;
    private boolean compatibilityMode;
    private List<TlsConstants.CipherSuite> supportedCiphers;
    private TlsConstants.CipherSuite selectedCipher;
    private List<Extension> extensions;
    private Status status = Status.Initial;
    private ClientHello clientHello;
    private TlsState state;
    private NewSessionTicket newSessionTicket;

    public TlsClientEngine(ClientMessageSender clientMessageSender) {
        sender = clientMessageSender;
        supportedCiphers = new ArrayList<>();
        extensions = new ArrayList<>();
    }

    public void startHandshake() throws IOException {
        generateKeys();
        if (serverName == null || supportedCiphers.isEmpty()) {
            throw new IllegalStateException("not all mandatory properties are set");
        }

        if (newSessionTicket != null) {
            TlsState tlsState = new TlsState(newSessionTicket.getPSK());
            extensions.add(new ClientHelloPreSharedKeyExtension(tlsState, newSessionTicket));
        }
        clientHello = new ClientHello(serverName, publicKey, compatibilityMode, supportedCiphers, supportedSignatures, extensions);
        sender.send(clientHello);
        status = Status.ClientHelloSent;
    }

    /**
     * Updates the (handshake) state with a received Server Hello message.
     * @param serverHello
     * @throws MissingExtensionAlert
     */
    public void received(ServerHello serverHello) throws MissingExtensionAlert, IllegalParameterAlert {
        boolean containsSupportedVersionExt = serverHello.getExtensions().stream().anyMatch(ext -> ext instanceof SupportedVersionsExtension);
        boolean containsKeyExt = serverHello.getExtensions().stream().anyMatch(ext -> ext instanceof PreSharedKeyExtension || ext instanceof KeyShareExtension);
        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "All TLS 1.3 ServerHello messages MUST contain the "supported_versions" extension.
        // Current ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share"
        // extension, or both (when using a PSK with (EC)DHE key establishment)."
        if (! containsSupportedVersionExt || !containsKeyExt) {
            throw new MissingExtensionAlert();
        }

        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        // "A server which negotiates TLS 1.3 MUST respond by sending a "supported_versions" extension containing the selected version value (0x0304)."
        short tlsVersion = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof SupportedVersionsExtension)
                .map(extension -> ((SupportedVersionsExtension) extension).getTlsVersion())
                .findFirst()
                .get();
        if (tlsVersion != 0x0304) {
            throw new IllegalParameterAlert("invalid tls version");
        }

        // https://tools.ietf.org/html/rfc8446#section-4.2
        // "If an implementation receives an extension which it recognizes and which is not specified for the message in
        // which it appears, it MUST abort the handshake with an "illegal_parameter" alert."
        if (serverHello.getExtensions().stream()
            .anyMatch(ext -> ! (ext instanceof SupportedVersionsExtension) &&
                    ! (ext instanceof PreSharedKeyExtension) &&
                    ! (ext instanceof KeyShareExtension))) {
            throw new IllegalParameterAlert("illegal extension in server hello");
        }

        Optional<KeyShareExtension.KeyShareEntry> keyShare = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof KeyShareExtension)
                // In the context of a server hello, the key share extension contains exactly one key share entry
                .map(extension -> ((KeyShareExtension) extension).getKeyShareEntries().get(0))
                .findFirst();

        Optional<Extension> preSharedKey = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof ServerPreSharedKeyExtension)
                .findFirst();

        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share" extension,
        // or both (when using a PSK with (EC)DHE key establishment)."
        if (keyShare.isEmpty() && preSharedKey.isEmpty()) {
            throw new MissingExtensionAlert(" either the pre_shared_key extension or the key_share extension must be present");
        }

        if (! supportedCiphers.contains(serverHello.getCipherSuite())) {
            // https://tools.ietf.org/html/rfc8446#section-4.1.3
            // "A client which receives a cipher suite that was not offered MUST abort the handshake with an "illegal_parameter" alert."
            throw new IllegalParameterAlert("cipher suite does not match");
        }
        selectedCipher = serverHello.getCipherSuite();

        state = (newSessionTicket == null)? new TlsState(): new TlsState(newSessionTicket.psk);

        state.clientHelloSend(privateKey, clientHello.getBytes());
        if (preSharedKey.isPresent()) {
            state.setPskSelected(((ServerPreSharedKeyExtension) preSharedKey.get()).getSelectedIdentity());
            Logger.debug("Server has accepted PSK key establishment");
        }
        if (keyShare.isPresent()) {
            state.setServerSharedKey(keyShare.get().getKey());
        }
        state.serverHelloReceived(serverHello.getBytes());
        status = Status.ServerHelloReceived;
    }

    public void received(EncryptedExtensions encryptedExtensions) throws TlsProtocolException {
        if (status != Status.ServerHelloReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.3.1
            // "the server MUST send the EncryptedExtensions message immediately after the ServerHello message"
            throw new UnexpectedMessageAlert("unexpected encrypted extensions message");
        }

        List<Class> clientExtensionTypes = extensions.stream()
                .map(extension -> extension.getClass()).collect(Collectors.toList());
        boolean allClientResponses = encryptedExtensions.getExtensions().stream()
                .allMatch(ext -> clientExtensionTypes.contains(ext.getClass()));
        if (! allClientResponses) {
            // https://tools.ietf.org/html/rfc8446#section-4.2
            // "Implementations MUST NOT send extension responses if the remote endpoint did not send the corresponding
            // extension requests, with the exception of the "cookie" extension in the HelloRetryRequest. Upon receiving
            // such an extension, an endpoint MUST abort the handshake with an "unsupported_extension" alert."
            throw new UnsupportedExtensionAlert("extension response to missing request");
        }

        int uniqueExtensions = encryptedExtensions.getExtensions().stream()
                .map(extension -> extension.getClass())
                .collect(Collectors.toSet())
                .size();
        if (uniqueExtensions != encryptedExtensions.getExtensions().size()) {
            // "There MUST NOT be more than one extension of the same type in a given extension block."
            throw new UnsupportedExtensionAlert("duplicate extensions not allowed");
        }

        state.encryptedExtensionsReceived(encryptedExtensions.getBytes());
        status = Status.EncryptedExtensionsReceived;
    }

    public void received(CertificateMessage certificateMessage) throws TlsProtocolException {
        if (status != Status.EncryptedExtensionsReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.4
            // "TLS generally uses a common set of messages for authentication, key confirmation, and handshake
            //   integrity: Certificate, CertificateVerify, and Finished.  (...)  These three messages are always
            //   sent as the last messages in their handshake flight."
            throw new UnexpectedMessageAlert("unexpected certificate message");
        }

        if (certificateMessage.getRequestContext().length > 0) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.2
            // "If this message is in response to a CertificateRequest, the value of certificate_request_context in that
            // message. Otherwise (in the case of server authentication), this field SHALL be zero length."
            throw new IllegalParameterAlert("certificate request context should be zero length");
        }
        if (certificateMessage.getEndEntityCertificate() == null) {
            throw new IllegalParameterAlert("missing certificate");
        }

        serverCertificate = certificateMessage.getEndEntityCertificate();

        state.setCertificate(certificateMessage.getBytes());
        status = Status.CertificateReceived;
    }

    public void received(CertificateVerifyMessage certificateVerifyMessage) throws TlsProtocolException {
        if (status != Status.CertificateReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.3
            // "When sent, this message MUST appear immediately after the Certificate message and immediately prior to
            // the Finished message."
            throw new UnexpectedMessageAlert("unexpected certificate verify message");
        }
        status = Status.CertificateVerifyReceived;
    }


    private void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(ecCurve));

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = (ECPrivateKey) keyPair.getPrivate();
            publicKey = (ECPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    protected boolean verifySignature(byte[] signatureToVerify, TlsConstants.SignatureScheme signatureScheme, Certificate certificate, byte[] transcriptHash) {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3
        // "The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteBuffer contentToSign = ByteBuffer.allocate(64 + "TLS 1.3, server CertificateVerify".getBytes(ISO_8859_1).length + 1 + transcriptHash.length);
        for (int i = 0; i < 64; i++) {
            contentToSign.put((byte) 0x20);
        }
        // "The context string for a server signature is
        //   "TLS 1.3, server CertificateVerify". "
        contentToSign.put("TLS 1.3, server CertificateVerify".getBytes(ISO_8859_1));
        contentToSign.put((byte) 0x00);
        // "The content that is covered
        //   under the signature is the hash output as described in Section 4.4.1,
        //   namely:
        //      Transcript-Hash(Handshake Context, Certificate)"
        contentToSign.put(transcriptHash);

        Signature signatureAlgorithm = null;
        // https://tools.ietf.org/html/rfc8446#section-9.1
        // "A TLS-compliant application MUST support digital signatures with rsa_pkcs1_sha256 (for certificates),
        // rsa_pss_rsae_sha256 (for CertificateVerify and certificates), and ecdsa_secp256r1_sha256."
        if (signatureScheme.equals(rsa_pss_rsae_sha256)) {
            try {
                signatureAlgorithm = Signature.getInstance("RSASSA-PSS");
                signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing RSASSA-PSS support");
            } catch (InvalidAlgorithmParameterException e) {
                // Fairly impossible (because the parameters is hard coded)
                throw new RuntimeException(e);
            }
        } else {
            // Bad lock, not yet supported.
            throw new RuntimeException("Signature algorithm (verification) not supported " + signatureScheme);
        }
        boolean verified = false;
        try {
            signatureAlgorithm.initVerify(certificate);
            signatureAlgorithm.update(contentToSign.array());
            verified = signatureAlgorithm.verify(signatureToVerify);
        } catch (InvalidKeyException e) {
            Logger.debug("Certificate verify: invalid key.");
        } catch (SignatureException e) {
            Logger.debug("Certificate verify: invalid signature.");
        }
        return verified;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public void setCompatibilityMode(boolean compatibilityMode) {
        this.compatibilityMode = compatibilityMode;
    }

    public void addSupportedCiphers(List<TlsConstants.CipherSuite> supportedCiphers) {
        this.supportedCiphers.addAll(supportedCiphers);
    }

    public void addExtensions(List<Extension> extensions) {
        this.extensions.addAll(extensions);
    }

    public void add(Extension extension) {
        extensions.add(extension);
    }

    public void setNewSessionTicket(NewSessionTicket newSessionTicket) {
        this.newSessionTicket = newSessionTicket;
    }

    public TlsConstants.CipherSuite getSelectedCipher() {
        if (selectedCipher != null) {
            return selectedCipher;
        }
        else {
            throw new IllegalStateException("No (valid) server hello received yet");
        }
    }

    public byte[] getClientEarlyTrafficSecret() {
        if (state != null) {
            return state.getClientEarlyTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getClientHandshakeTrafficSecret() {
        if (state != null) {
            return state.getClientHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getServerHandshakeTrafficSecret() {
        if (state != null) {
            return state.getServerHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getClientApplicationTrafficSecret() {
        if (state != null) {
            return state.getClientApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getServerApplicationTrafficSecret() {
        if (state != null) {
            return state.getServerApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }


    // TODO: remove this
    public TlsState getState() {
        return state;
    }
}
