package net.luminis.tls;

import net.luminis.tls.handshake.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TranscriptHashTest {

    private TranscriptHash transcriptHash;

    @BeforeEach
    void initObjectUnderTest() {
        transcriptHash = new TranscriptHash(32);
    }

    @Test
    void computeSingleMessageHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        transcriptHash.record(ch);

        assertThat(transcriptHash.getHash(TlsConstants.HandshakeType.client_hello)).isEqualTo(computeHash(new byte[] { 0x01 }));
    }

    @Test
    void computeMessageSequenceHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        ServerHello sh = mock(ServerHello.class);
        when(sh.getType()).thenReturn(TlsConstants.HandshakeType.server_hello);
        when(sh.getBytes()).thenReturn(new byte[] { 0x02 });

        EncryptedExtensions ee = mock(EncryptedExtensions.class);
        when(ee.getType()).thenReturn(TlsConstants.HandshakeType.encrypted_extensions);
        when(ee.getBytes()).thenReturn(new byte[] { 0x03 });

        CertificateMessage cm = mock(CertificateMessage.class);
        when(cm.getType()).thenReturn(TlsConstants.HandshakeType.certificate);
        when(cm.getBytes()).thenReturn(new byte[] { 0x04 });

        transcriptHash.record(ch);
        transcriptHash.record(sh);
        transcriptHash.record(ee);
        transcriptHash.record(cm);

        byte[] expected = computeHash(new byte[]{ 0x01 }, new byte[]{ 0x02 }, new byte[]{ 0x03 }, new byte[]{ 0x04 });
        assertThat(transcriptHash.getHash(TlsConstants.HandshakeType.certificate)).isEqualTo(expected);
    }

    @Test
    void computeMessageSequenceWithMissingMessagesHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        ServerHello sh = mock(ServerHello.class);
        when(sh.getType()).thenReturn(TlsConstants.HandshakeType.server_hello);
        when(sh.getBytes()).thenReturn(new byte[] { 0x02 });

        EncryptedExtensions ee = mock(EncryptedExtensions.class);
        when(ee.getType()).thenReturn(TlsConstants.HandshakeType.encrypted_extensions);
        when(ee.getBytes()).thenReturn(new byte[] { 0x03 });

        // No certificate message
        // No certificate verify message

        FinishedMessage sf = mock(FinishedMessage.class);
        when(sf.getType()).thenReturn(TlsConstants.HandshakeType.finished);
        when(sf.getBytes()).thenReturn(new byte[] { 0x06 });

        transcriptHash.record(ch);
        transcriptHash.record(sh);
        transcriptHash.record(ee);
        transcriptHash.recordServer(sf);

        byte[] expected = computeHash(new byte[]{ 0x01 }, new byte[]{ 0x02 }, new byte[]{ 0x03 }, new byte[]{ 0x06 });
        assertThat(transcriptHash.getServerHash(TlsConstants.HandshakeType.finished)).isEqualTo(expected);
    }

    private byte[] computeHash(byte[]... elements) throws Exception {
        String hashAlgorithm = "SHA-256";
        MessageDigest hashFunction = MessageDigest.getInstance(hashAlgorithm);
        for (byte[] data: elements) {
            hashFunction.update(data);
        }
        return hashFunction.digest();
    }

}