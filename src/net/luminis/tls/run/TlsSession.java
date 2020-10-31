package net.luminis.tls.run;

import net.luminis.tls.*;
import net.luminis.tls.alert.AlertRecord;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;
import net.luminis.tls.record.ApplicationData;
import net.luminis.tls.record.ChangeCipherSpec;
import net.luminis.tls.record.HandshakeRecord;
import net.luminis.tls.util.ByteUtils;

import java.io.*;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;


public class TlsSession implements ClientMessageSender {

    private final PrivateKey clientPrivateKey;
    private final ECPublicKey clientPublicKey;
    private final PushbackInputStream input;
    private final OutputStream output;
    private TlsState state;
    private List<NewSessionTicketMessage> newSessionTicketMessages;
    private Consumer<NewSessionTicket> newSessionTicketCallback;
    private TlsClientEngine tlsClientEngine;


    public TlsSession(NewSessionTicket newSessionTicket, PrivateKey clientPrivateKey, ECPublicKey clientPublicKey, InputStream input, OutputStream output, String serverName) throws IOException, TlsProtocolException {
        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = new PushbackInputStream(input, 16);;
        this.output = output;
        newSessionTicketMessages = new CopyOnWriteArrayList<>();

        tlsClientEngine = new TlsClientEngine(this, new TlsStatusEventHandler() {
            @Override
            public void earlySecretsKnown() {}

            @Override
            public void handshakeSecretsKnown() {}

            @Override
            public void handshakeFinished() {}

            @Override
            public void newSessionTicketReceived(NewSessionTicket ticket) {}

            @Override
            public void extensionsReceived(List<Extension> extensions) {}
        });

        tlsClientEngine.setServerName(serverName);
        tlsClientEngine.addSupportedCiphers(List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256));

        if (newSessionTicket != null) {
            tlsClientEngine.setNewSessionTicket(newSessionTicket);
        }
    }

    public void start() throws IOException, TlsProtocolException {
        tlsClientEngine.startHandshake();

        parseServerMessages(tlsClientEngine);
    }

    @Override
    public void send(ClientHello clientHello) throws IOException {
        HandshakeRecord handshakeRecord = new HandshakeRecord(clientHello);
        output.write(handshakeRecord.getBytes());
        output.flush();

        Logger.debug("Sent Client Hello: " + ByteUtils.bytesToHex(clientHello.getBytes()));
    }

    @Override
    public void send(FinishedMessage finishedMessage) throws IOException {
        ApplicationData applicationDataRecord = new ApplicationData(finishedMessage, state);
        output.write(applicationDataRecord.getBytes());
        output.flush();

        Logger.debug("Sent Finished: " + ByteUtils.bytesToHex(applicationDataRecord.getBytes()));
        Logger.debug("Handshake done!");
    }

    public void sendApplicationData(byte[] data) throws IOException, TlsProtocolException {
        ApplicationData applicationDataRecord;
        applicationDataRecord = new ApplicationData(data, state);
        output.write(applicationDataRecord.getBytes());
        output.flush();
        Logger.debug("Application data sent: " + ByteUtils.bytesToHex(applicationDataRecord.getBytes()));

        parseServerMessages(tlsClientEngine);
    }

    private void parseServerMessages(TlsClientEngine tlsClientEngine) throws IOException, TlsProtocolException {
        int contentType = input.read();

        while (contentType != -1) {
            input.unread(contentType);

            switch (contentType) {
                case 0:
                    throw new RuntimeException("Record type is 0 (invalid)");
                case 20:
                    new ChangeCipherSpec().parse(input);
                    break;
                case 21:
                    new AlertRecord().parse(input);
                    break;
                case 22:
                    new HandshakeRecord().parse(input, tlsClientEngine);
                    state = tlsClientEngine.getState();
                    break;
                case 23:
                    new ApplicationData().parse(input, state, tlsClientEngine);
                    if (!tlsClientEngine.getNewSessionTickets().isEmpty()) {
                        newSessionTicketCallback.accept(tlsClientEngine.getNewSessionTickets().get(0));
                    }
                    break;
                default:
                    throw new RuntimeException("Record type is unknown (" + contentType + ")");
            }
            if (tlsClientEngine.handshakeFinished()) {
                break;
            }
            contentType = input.read();
        }
    }

    public NewSessionTicket getNewSessionTicket(int index) {
        return tlsClientEngine.getNewSessionTickets().get(index);
    }

    public void setNewSessionTicketCallback(Consumer<NewSessionTicket> callback) {
        newSessionTicketCallback = callback;
    }
}
