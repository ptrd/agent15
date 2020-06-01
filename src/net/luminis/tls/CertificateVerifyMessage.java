package net.luminis.tls;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.stream.Stream;

// https://tools.ietf.org/html/rfc8446#section-4.4.3
// "Certificate Verify
//   This message is used to provide explicit proof that an endpoint possesses the private key corresponding to its certificate.  The
//   CertificateVerify message also provides integrity for the handshake up to this point.  Servers MUST send this message when authenticating
//   via a certificate.  Clients MUST send this message whenever authenticating via a certificate (i.e., when the Certificate message
//   is non-empty). "
public class CertificateVerifyMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 2 + 2 + 1;
    private TlsConstants.SignatureScheme signatureScheme;
    private byte[] signature;

    public CertificateVerifyMessage parse(ByteBuffer buffer, int length, TlsState state) throws TlsProtocolException {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate_verify, MINIMUM_MESSAGE_SIZE);

        try {
            short signatureSchemeValue = buffer.getShort();
            signatureScheme = Stream.of(TlsConstants.SignatureScheme.values())
                    .filter(it -> it.value == signatureSchemeValue)
                    .findAny()
                    .orElseThrow(() -> new DecodeErrorException("Unknown signature schema"));

            short signatureLength = buffer.getShort();
            signature = new byte[signatureLength];
            buffer.get(signature);
            if (buffer.position() - startPosition != 4 + remainingLength) {
                throw new DecodeErrorException("Incorrect message length");
            }

            // Update state.
            byte[] raw = new byte[length];
            buffer.position(startPosition);
            buffer.get(raw);
            state.setCertificateVerify(raw);

            return this;
        }
        catch (BufferUnderflowException notEnoughBytes) {
            throw new DecodeErrorException("message underflow");
        }
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public TlsConstants.SignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public byte[] getSignature() {
        return signature;
    }
}
