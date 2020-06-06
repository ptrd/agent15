package net.luminis.tls;

import java.io.ByteArrayInputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

// https://tools.ietf.org/html/rfc8446#section-4.4.2
public class CertificateMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 3 + 3 + 2;
    private byte[] requestContext;
    private X509Certificate endEntityCertificate;
    private List<X509Certificate> certificateChain = new ArrayList<>();

    public CertificateMessage(X509Certificate certificate) {
        this.requestContext = new byte[0];
        endEntityCertificate = certificate;
    }

    public CertificateMessage(byte[] requestContext, X509Certificate certificate) {
        this.requestContext = requestContext;
        endEntityCertificate = certificate;
    }

    public CertificateMessage() {
    }

    public CertificateMessage parse(ByteBuffer buffer, TlsState state) throws DecodeErrorException, BadCertificateAlert {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate, MINIMUM_MESSAGE_SIZE);

        try {
            int certificateRequestContextSize = buffer.get() & 0xff;
            if (certificateRequestContextSize > 0) {
                requestContext = new byte[certificateRequestContextSize];
                buffer.get(requestContext);
            }
            else {
                requestContext = new byte[0];
            }
            parseCertificateEntries(buffer);

            // Update state.
            byte[] raw = new byte[4 + remainingLength];
            buffer.position(startPosition);
            buffer.get(raw);
            state.setCertificate(raw);

            return this;
        }
        catch (BufferUnderflowException notEnoughBytes) {
            throw new DecodeErrorException("message underflow");
        }
    }

    private int parseCertificateEntries(ByteBuffer buffer) throws BadCertificateAlert {
        int certificateListSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        int remainingCertificateBytes = certificateListSize;
        int certCount = 0;

        while (remainingCertificateBytes > 0) {
            int certSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
            byte[] certificateData = new byte[certSize];
            buffer.get(certificateData);

            if (certSize > 0) {
                // https://tools.ietf.org/html/rfc8446#section-4.4.2
                // "If the corresponding certificate type extension ("server_certificate_type" or "client_certificate_type")
                // was not negotiated in EncryptedExtensions, or the X.509 certificate type was negotiated, then each
                // CertificateEntry contains a DER-encoded X.509 certificate."
                // This implementation does not support raw-public-key certificates, so the only type supported is X509.
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
                    if (certCount == 0) {
                        // https://tools.ietf.org/html/rfc8446#section-4.4.2
                        // "The sender's certificate MUST come in the first CertificateEntry in the list. "
                        endEntityCertificate = certificate;
                    }
                    certificateChain.add(certificate);
                } catch (CertificateException e) {
                    throw new BadCertificateAlert("could not parse certificate");
                }
            }

            remainingCertificateBytes -= (3 + certSize);
            certCount++;
            int extensionsSize = buffer.getShort();
            if (extensionsSize > 0) {
                // https://tools.ietf.org/html/rfc8446#section-4.4.2
                // "Valid extensions for server certificates at present include the OCSP Status extension [RFC6066]
                // and the SignedCertificateTimestamp extension [RFC6962];..."
                // None of them is (yet) supported by this implementation.
                byte[] extensionData = new byte[extensionsSize];
                buffer.get(extensionData);
            }
            remainingCertificateBytes -= (2 + extensionsSize);
        }
        return certCount;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public byte[] getRequestContext() {
        return requestContext;
    }

    public X509Certificate getEndEntityCertificate() {
        return endEntityCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }
}
