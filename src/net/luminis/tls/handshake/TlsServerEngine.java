package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;
import net.luminis.tls.TranscriptHash;
import net.luminis.tls.alert.HandshakeFailureAlert;
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

import static net.luminis.tls.TlsConstants.NamedGroup.secp256r1;
import static net.luminis.tls.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;

public class TlsServerEngine extends TlsEngine implements ServerMessageProcessor {

    private final ArrayList<Object> supportedCiphers;
    private final ArrayList<Object> extensions;
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
        extensions = new ArrayList<>();
        transcriptHash = new TranscriptHash(32);
    }

    @Override
    public void received(ClientHello clientHello) throws TlsProtocolException, IOException {
        throw new HandshakeFailureAlert("negotiation failed");
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

