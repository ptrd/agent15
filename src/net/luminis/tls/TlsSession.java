package net.luminis.tls;

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

        tlsClientEngine = new TlsClientEngine(this);
        tlsClientEngine.setServerName(serverName);
        tlsClientEngine.addSupportedCiphers(List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256));

        if (newSessionTicket != null) {
            tlsClientEngine.setNewSessionTicket(newSessionTicket);
        }
        tlsClientEngine.startHandshake();

        parseServerMessages(tlsClientEngine);
        state = tlsClientEngine.getState();

        sendChangeCipherSpec(output);
        sendClientFinished(output);

        state.computeApplicationSecrets();
    }

    public TlsSession(byte[] sentClientHello, PrivateKey clientPrivateKey, ECPublicKey clientPublicKey, InputStream input, OutputStream output) throws IOException, TlsProtocolException {

        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = new PushbackInputStream(input, 16);
        this.output = output;

        state = new TlsState(null);
        state.clientHelloSend(clientPrivateKey, sentClientHello);
        parseServerMessages(tlsClientEngine);

        sendChangeCipherSpec(output);
        sendClientFinished(output);

        state.computeApplicationSecrets();
        sendApplicationData("GET / HTTP/1.1\r\n\r\n".getBytes());
    }

    public void send(ClientHello clientHello) throws IOException {
        HandshakeRecord handshakeRecord = new HandshakeRecord(clientHello);
        output.write(handshakeRecord.getBytes());
        output.flush();

        Logger.debug("Sent Client Hello: " + ByteUtils.bytesToHex(clientHello.getBytes()));
    }

    private void sendChangeCipherSpec(OutputStream output) throws IOException {
        byte[] changeCipherSpec = new byte[] {
                0x14, 0x03, 0x03, 0x00, 0x01, 0x01
        };
        output.write(changeCipherSpec);
        output.flush();
        Logger.debug("Sent (legacy) Change Cipher Spec: " + ByteUtils.bytesToHex(changeCipherSpec));
    }

    private void sendClientFinished(OutputStream output) throws IOException {
        ApplicationData applicationDataRecord = new ApplicationData(new FinishedMessage(state), state);
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
                    new HandshakeRecord().parse(input, state, tlsClientEngine);
                    state = tlsClientEngine.getState();
                    break;
                case 23:
                    List<Message> messages = new ApplicationData().parse(input, state, tlsClientEngine).getMessages();
                    messages.stream()
                            .filter(m -> m instanceof NewSessionTicketMessage)
                            .findAny()
                            .stream()
                            .forEach(m -> addNewSessionTicket((NewSessionTicketMessage) m));

                    if (state.isServerFinished()) {
                        return;
                    }
                    break;
                default:
                    throw new RuntimeException("Record type is unknown (" + contentType + ")");
            }
            contentType = input.read();
        }
    }

    private void addNewSessionTicket(NewSessionTicketMessage m) {
        newSessionTicketMessages.add(m);
        if (newSessionTicketCallback != null) {
            newSessionTicketCallback.accept(new NewSessionTicket(state, m));
        }
    }

    public int getNewSessionTicketCount() {
        return newSessionTicketMessages.size();
    }

    public NewSessionTicket getNewSessionTicket(int index) {
        if (index < newSessionTicketMessages.size()) {
            return new NewSessionTicket(state, newSessionTicketMessages.get(index));
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    public void setNewSessionTicketCallback(Consumer<NewSessionTicket> callback) {
        newSessionTicketCallback = callback;
    }
}
