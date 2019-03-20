package net.luminis.tls;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.4.2
public class CertificateMessage extends HandshakeMessage {

    public CertificateMessage parse(ByteBuffer buffer, int length, TlsState state) {
        int startPosition = buffer.position();

        Logger.debug("Certificate message:\n" + ByteUtils.byteToHexBlock(buffer, buffer.position(), Math.min(length, buffer.remaining())));
        if (length > buffer.remaining()) {
            Logger.debug("Underflow: expecting " + length + " bytes, but only " + buffer.remaining() + " left!");
        }

        int handshakeType = buffer.get();  // Should be certificate.value
        int remainingLength = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);  // Length parameter is derived from this value....)

        int certificateRequestContextSize = buffer.get();
        if (certificateRequestContextSize > 0) {
            byte[] certificateRequestContext = new byte[certificateRequestContextSize];
            buffer.get(certificateRequestContext);
        }

        int certificateListSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);

        int certCount = parseCertificateEntry(buffer, certificateListSize);

        Logger.debug("Got Certificate message (" + length + " bytes), contains " + certCount + " certificate" + (certCount == 1? ".": "s."));

        // Update state.
        byte[] raw = new byte[length];
        buffer.position(startPosition);
        buffer.get(raw);
        state.setCertificate(raw);

        return this;
    }

    private int parseCertificateEntry(ByteBuffer buffer, int certificateListSize) {
        int remainingCertificateBytes = certificateListSize;
        int certCount = 0;

        while (remainingCertificateBytes > 0) {
            int certSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
            byte[] cert_data = new byte[certSize];
            buffer.get(cert_data);
            remainingCertificateBytes -= (3 + certSize);
            certCount++;
            // TODO: when processing the certificate data, the type (X509 or RawPublicKey) was negotiated in EncryptedExtensions!
            int extensionsSize = buffer.getShort();
            if (extensionsSize > 0)
                buffer.get(new byte[extensionsSize]);
            remainingCertificateBytes -= (2 + extensionsSize);
        }
        return certCount;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
