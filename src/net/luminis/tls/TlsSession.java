package net.luminis.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;


public class TlsSession {

    private final PrivateKey clientPrivateKey;
    private final ECPublicKey clientPublicKey;
    private final PushbackInputStream input;
    private final OutputStream output;
    private final TlsState state;
    private List<NewSessionTicketMessage> newSessionTicketMessages;
    private Consumer<NewSessionTicket> newSessionTicketCallback;


    public TlsSession(PrivateKey clientPrivateKey, ECPublicKey clientPublicKey, InputStream input, OutputStream output, String serverName) throws IOException, TlsProtocolException {
        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = new PushbackInputStream(input, 16);;
        this.output = output;
        state = new TlsState();
        newSessionTicketMessages = new CopyOnWriteArrayList<>();

        sendClientHello(serverName);
        parseServerMessages();

        sendChangeCipherSpec(output);
        sendClientFinished(output);

        state.computeApplicationSecrets();
    }

    public TlsSession(byte[] sentClientHello, PrivateKey clientPrivateKey, ECPublicKey clientPublicKey, InputStream input, OutputStream output) throws IOException, TlsProtocolException {

        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = new PushbackInputStream(input, 16);
        this.output = output;

        state = new TlsState();
        state.clientHelloSend(clientPrivateKey, sentClientHello);
        parseServerMessages();

        sendChangeCipherSpec(output);
        sendClientFinished(output);

        state.computeApplicationSecrets();
        sendApplicationData("GET / HTTP/1.1\r\n\r\n".getBytes());
    }

    private void sendClientHello(String serverName) throws IOException {
        ClientHello clientHello = new ClientHello(serverName, clientPublicKey);
        HandshakeRecord handshakeRecord = new HandshakeRecord(clientHello);
        output.write(handshakeRecord.getBytes());
        output.flush();
        state.clientHelloSend(clientPrivateKey, clientHello.getBytes());
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

        parseServerMessages();
    }


    private void parseServerMessages() throws IOException, TlsProtocolException {
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
                    new HandshakeRecord().parse(input, state);
                    break;
                case 23:
                    List<Message> messages = new ApplicationData().parse(input, state).getMessages();
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
