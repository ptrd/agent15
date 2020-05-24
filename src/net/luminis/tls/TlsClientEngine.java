package net.luminis.tls;

import net.luminis.tls.exception.MissingExtensionAlert;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.KeyShareExtension;
import net.luminis.tls.extension.SupportedVersionsExtension;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class TlsClientEngine implements TrafficSecrets {

    private final ClientMessageSender sender;
    private String serverName;
    private String ecCurve = "secp256r1";
    private ECPublicKey publicKey;
    private ECPrivateKey privateKey;
    private boolean compatibilityMode;
    private List<TlsConstants.CipherSuite> supportedCiphers;
    private TlsConstants.CipherSuite selectedCipher;
    private List<Extension> extensions;
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
        clientHello = new ClientHello(serverName, publicKey, compatibilityMode, supportedCiphers, extensions);
        sender.send(clientHello);
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
            // https://tools.ietf.org/html/rfc8446#section-4.3.1
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
