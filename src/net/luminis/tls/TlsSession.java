package net.luminis.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TlsSession {


    private final byte[] sentClientHello;
    private final PrivateKey clientPrivateKey;
    private final PublicKey clientPublicKey;
    private final InputStream input;
    private final TlsState state;

    public TlsSession(byte[] sentClientHello, PrivateKey clientPrivateKey, PublicKey clientPublicKey, InputStream input, OutputStream output) throws IOException, TlsProtocolException {

        this.sentClientHello = sentClientHello;
        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = input;

        state = new TlsState();
        state.clientHelloSend(clientPrivateKey, sentClientHello);
        PushbackInputStream inputStream = new PushbackInputStream(input, 16);
        parseServerMessages(inputStream);

        // Send Client Change Cipher Spec
        byte[] changeCipherSpec = new byte[] {
                0x14, 0x03, 0x03, 0x00, 0x01, 0x01
        };
        output.write(changeCipherSpec);
        output.flush();
        Logger.debug("Sent (legacy) Change Cipher Spec: " + ByteUtils.bytesToHex(changeCipherSpec));

        // Send Finished
        ApplicationData applicationDataRecord = new ApplicationData(new FinishedMessage(state), state);
        output.write(applicationDataRecord.getBytes());
        output.flush();
        Logger.debug("Sent Finished: " + ByteUtils.bytesToHex(applicationDataRecord.getBytes()));
        Logger.debug("Handshake done!");

        state.computeApplicationSecrets();

        // Send application data
        applicationDataRecord = new ApplicationData("GET / HTTP/1.1\r\n\r\n".getBytes(), state);
        output.write(applicationDataRecord.getBytes());
        output.flush();
        Logger.debug("GET request sent: " + ByteUtils.bytesToHex(applicationDataRecord.getBytes()));

        parseServerMessages(inputStream);
    }

    private void parseServerMessages(PushbackInputStream input) throws IOException, TlsProtocolException {
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
                    new ApplicationData().parse(input, state);
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

}
