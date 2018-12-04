
import at.favre.lib.crypto.HKDF;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class TheNewIllustratedTlsConnection {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");
    private static byte[] serverHandshakeKey;
    private static byte[] serverHandshakeIV;


    public static void main(String[] args) throws Exception {

        byte[] helloHash = computeHandshakeMessagesHash();

        byte[] sharedSecret = hexToBytes("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");
        computeSecrets(helloHash, sharedSecret);

        byte[] decryptedData = decryptWrapper(serverHandshakeKey, serverHandshakeIV, 0);
    }

    private static byte[] decryptWrapper(byte[] serverHandshakeKey, byte[] serverIV, int recordCount) throws Exception {
        byte[] wrapper = new byte[] {
                (byte) 0x17, (byte) 0x03, (byte) 0x03, (byte) 0x04, (byte) 0x75, (byte) 0xda, (byte) 0x1e, (byte) 0xc2,
                (byte) 0xd7, (byte) 0xbd, (byte) 0xa8, (byte) 0xeb, (byte) 0xf7, (byte) 0x3e, (byte) 0xdd, (byte) 0x50,
                (byte) 0x10, (byte) 0xfb, (byte) 0xa8, (byte) 0x08, (byte) 0x9f, (byte) 0xd4, (byte) 0x26, (byte) 0xb0,
                (byte) 0xea, (byte) 0x1e, (byte) 0xa4, (byte) 0xd8, (byte) 0x8d, (byte) 0x07, (byte) 0x4f, (byte) 0xfe,
                (byte) 0xa8, (byte) 0xa9, (byte) 0x87, (byte) 0x3a, (byte) 0xf5, (byte) 0xf5, (byte) 0x02, (byte) 0x26,
                (byte) 0x1e, (byte) 0x34, (byte) 0xb1, (byte) 0x56, (byte) 0x33, (byte) 0x43, (byte) 0xe9, (byte) 0xbe,
                (byte) 0xb6, (byte) 0x13, (byte) 0x2e, (byte) 0x7e, (byte) 0x83, (byte) 0x6d, (byte) 0x65, (byte) 0xdb,
                (byte) 0x6d, (byte) 0xcf, (byte) 0x00, (byte) 0xbc, (byte) 0x40, (byte) 0x19, (byte) 0x35, (byte) 0xae,
                (byte) 0x36, (byte) 0x9c, (byte) 0x44, (byte) 0x0d, (byte) 0x67, (byte) 0xaf, (byte) 0x71, (byte) 0x9e,
                (byte) 0xc0, (byte) 0x3b, (byte) 0x98, (byte) 0x4c, (byte) 0x45, (byte) 0x21, (byte) 0xb9, (byte) 0x05,
                (byte) 0xd5, (byte) 0x8b, (byte) 0xa2, (byte) 0x19, (byte) 0x7c, (byte) 0x45, (byte) 0xc4, (byte) 0xf7,
                (byte) 0x73, (byte) 0xbd, (byte) 0x9d, (byte) 0xd1, (byte) 0x21, (byte) 0xb4, (byte) 0xd2, (byte) 0xd4,
                (byte) 0xe6, (byte) 0xad, (byte) 0xff, (byte) 0xfa, (byte) 0x27, (byte) 0xc2, (byte) 0xa8, (byte) 0x1a,
                (byte) 0x99, (byte) 0xa8, (byte) 0xef, (byte) 0xe8, (byte) 0x56, (byte) 0xc3, (byte) 0x5e, (byte) 0xe0,
                (byte) 0x8b, (byte) 0x71, (byte) 0xb3, (byte) 0xe4, (byte) 0x41, (byte) 0xbb, (byte) 0xec, (byte) 0xaa,
                (byte) 0x65, (byte) 0xfe, (byte) 0x72, (byte) 0x08, (byte) 0x15, (byte) 0xca, (byte) 0xb5, (byte) 0x8d,
                (byte) 0xb3, (byte) 0xef, (byte) 0xa8, (byte) 0xd1, (byte) 0xe5, (byte) 0xb7, (byte) 0x1c, (byte) 0x58,
                (byte) 0xe8, (byte) 0xd1, (byte) 0xfd, (byte) 0xb6, (byte) 0xb2, (byte) 0x1b, (byte) 0xfc, (byte) 0x66,
                (byte) 0xa9, (byte) 0x86, (byte) 0x5f, (byte) 0x85, (byte) 0x2c, (byte) 0x1b, (byte) 0x4b, (byte) 0x64,
                (byte) 0x0e, (byte) 0x94, (byte) 0xbd, (byte) 0x90, (byte) 0x84, (byte) 0x69, (byte) 0xe7, (byte) 0x15,
                (byte) 0x1f, (byte) 0x9b, (byte) 0xbc, (byte) 0xa3, (byte) 0xce, (byte) 0x53, (byte) 0x22, (byte) 0x4a,
                (byte) 0x27, (byte) 0x06, (byte) 0x2c, (byte) 0xeb, (byte) 0x24, (byte) 0x0a, (byte) 0x10, (byte) 0x5b,
                (byte) 0xd3, (byte) 0x13, (byte) 0x2d, (byte) 0xc1, (byte) 0x85, (byte) 0x44, (byte) 0x47, (byte) 0x77,
                (byte) 0x94, (byte) 0xc3, (byte) 0x73, (byte) 0xbc, (byte) 0x0f, (byte) 0xb5, (byte) 0xa2, (byte) 0x67,
                (byte) 0x88, (byte) 0x5c, (byte) 0x85, (byte) 0x7d, (byte) 0x4c, (byte) 0xcb, (byte) 0x4d, (byte) 0x31,
                (byte) 0x74, (byte) 0x2b, (byte) 0x7a, (byte) 0x29, (byte) 0x62, (byte) 0x40, (byte) 0x29, (byte) 0xfd,
                (byte) 0x05, (byte) 0x94, (byte) 0x0d, (byte) 0xe3, (byte) 0xf9, (byte) 0xf9, (byte) 0xb6, (byte) 0xe0,
                (byte) 0xa9, (byte) 0xa2, (byte) 0x37, (byte) 0x67, (byte) 0x2b, (byte) 0xc6, (byte) 0x24, (byte) 0xba,
                (byte) 0x28, (byte) 0x93, (byte) 0xa2, (byte) 0x17, (byte) 0x09, (byte) 0x83, (byte) 0x3c, (byte) 0x52,
                (byte) 0x76, (byte) 0xd4, (byte) 0x13, (byte) 0x63, (byte) 0x1b, (byte) 0xdd, (byte) 0xe6, (byte) 0xae,
                (byte) 0x70, (byte) 0x08, (byte) 0xc6, (byte) 0x97, (byte) 0xa8, (byte) 0xef, (byte) 0x42, (byte) 0x8a,
                (byte) 0x79, (byte) 0xdb, (byte) 0xf6, (byte) 0xe8, (byte) 0xbb, (byte) 0xeb, (byte) 0x47, (byte) 0xc4,
                (byte) 0xe4, (byte) 0x08, (byte) 0xef, (byte) 0x65, (byte) 0x6d, (byte) 0x9d, (byte) 0xc1, (byte) 0x9b,
                (byte) 0x8b, (byte) 0x5d, (byte) 0x49, (byte) 0xbc, (byte) 0x09, (byte) 0x1e, (byte) 0x21, (byte) 0x77,
                (byte) 0x35, (byte) 0x75, (byte) 0x94, (byte) 0xc8, (byte) 0xac, (byte) 0xd4, (byte) 0x1c, (byte) 0x10,
                (byte) 0x1c, (byte) 0x77, (byte) 0x50, (byte) 0xcb, (byte) 0x11, (byte) 0xb5, (byte) 0xbe, (byte) 0x6a,
                (byte) 0x19, (byte) 0x4b, (byte) 0x8f, (byte) 0x87, (byte) 0x70, (byte) 0x88, (byte) 0xc9, (byte) 0x82,
                (byte) 0x8e, (byte) 0x35, (byte) 0x07, (byte) 0xda, (byte) 0xda, (byte) 0x17, (byte) 0xbb, (byte) 0x14,
                (byte) 0xbb, (byte) 0x2c, (byte) 0x73, (byte) 0x89, (byte) 0x03, (byte) 0xc7, (byte) 0xaa, (byte) 0xb4,
                (byte) 0x0c, (byte) 0x54, (byte) 0x5c, (byte) 0x46, (byte) 0xaa, (byte) 0x53, (byte) 0x82, (byte) 0x3b,
                (byte) 0x12, (byte) 0x01, (byte) 0x81, (byte) 0xa1, (byte) 0x6c, (byte) 0xe9, (byte) 0x28, (byte) 0x76,
                (byte) 0x28, (byte) 0x8c, (byte) 0x4a, (byte) 0xcd, (byte) 0x81, (byte) 0x5b, (byte) 0x23, (byte) 0x3d,
                (byte) 0x96, (byte) 0xbb, (byte) 0x57, (byte) 0x2b, (byte) 0x16, (byte) 0x2e, (byte) 0xc1, (byte) 0xb9,
                (byte) 0xd7, (byte) 0x12, (byte) 0xf2, (byte) 0xc3, (byte) 0x96, (byte) 0x6c, (byte) 0xaa, (byte) 0xc9,
                (byte) 0xcf, (byte) 0x17, (byte) 0x4f, (byte) 0x3a, (byte) 0xed, (byte) 0xfe, (byte) 0xc4, (byte) 0xd1,
                (byte) 0x9f, (byte) 0xf9, (byte) 0xa8, (byte) 0x7f, (byte) 0x8e, (byte) 0x21, (byte) 0xe8, (byte) 0xe1,
                (byte) 0xa9, (byte) 0x78, (byte) 0x9b, (byte) 0x49, (byte) 0x0b, (byte) 0xa0, (byte) 0x5f, (byte) 0x1d,
                (byte) 0xeb, (byte) 0xd2, (byte) 0x17, (byte) 0x32, (byte) 0xfb, (byte) 0x2e, (byte) 0x15, (byte) 0xa0,
                (byte) 0x17, (byte) 0xc4, (byte) 0x75, (byte) 0xc4, (byte) 0xfd, (byte) 0x00, (byte) 0xbe, (byte) 0x04,
                (byte) 0x21, (byte) 0x86, (byte) 0xdc, (byte) 0x29, (byte) 0xe6, (byte) 0x8b, (byte) 0xb7, (byte) 0xec,
                (byte) 0xe1, (byte) 0x92, (byte) 0x43, (byte) 0x8f, (byte) 0x3b, (byte) 0x0c, (byte) 0x5e, (byte) 0xf8,
                (byte) 0xe4, (byte) 0xa5, (byte) 0x35, (byte) 0x83, (byte) 0xa0, (byte) 0x19, (byte) 0x43, (byte) 0xcf,
                (byte) 0x84, (byte) 0xbb, (byte) 0xa5, (byte) 0x84, (byte) 0x21, (byte) 0x73, (byte) 0xa6, (byte) 0xb3,
                (byte) 0xa7, (byte) 0x28, (byte) 0x95, (byte) 0x66, (byte) 0x68, (byte) 0x7c, (byte) 0x30, (byte) 0x18,
                (byte) 0xf7, (byte) 0x64, (byte) 0xab, (byte) 0x18, (byte) 0x10, (byte) 0x31, (byte) 0x69, (byte) 0x91,
                (byte) 0x93, (byte) 0x28, (byte) 0x71, (byte) 0x3c, (byte) 0x3b, (byte) 0xd4, (byte) 0x63, (byte) 0xd3,
                (byte) 0x39, (byte) 0x8a, (byte) 0x1f, (byte) 0xeb, (byte) 0x8e, (byte) 0x68, (byte) 0xe4, (byte) 0x4c,
                (byte) 0xfe, (byte) 0x48, (byte) 0x2f, (byte) 0x72, (byte) 0x84, (byte) 0x7f, (byte) 0x46, (byte) 0xc8,
                (byte) 0x0e, (byte) 0x6c, (byte) 0xc7, (byte) 0xf6, (byte) 0xcc, (byte) 0xf1, (byte) 0x79, (byte) 0xf4,
                (byte) 0x82, (byte) 0xc8, (byte) 0x88, (byte) 0x59, (byte) 0x4e, (byte) 0x76, (byte) 0x27, (byte) 0x66,
                (byte) 0x53, (byte) 0xb4, (byte) 0x83, (byte) 0x98, (byte) 0xa2, (byte) 0x6c, (byte) 0x7c, (byte) 0x9e,
                (byte) 0x42, (byte) 0x0c, (byte) 0xb6, (byte) 0xc1, (byte) 0xd3, (byte) 0xbc, (byte) 0x76, (byte) 0x46,
                (byte) 0xf3, (byte) 0x3b, (byte) 0xb8, (byte) 0x32, (byte) 0xbf, (byte) 0xba, (byte) 0x98, (byte) 0x48,
                (byte) 0x9c, (byte) 0xad, (byte) 0xfb, (byte) 0xd5, (byte) 0x5d, (byte) 0xd8, (byte) 0xb2, (byte) 0xc5,
                (byte) 0x76, (byte) 0x87, (byte) 0xa4, (byte) 0x7a, (byte) 0xcb, (byte) 0xa4, (byte) 0xab, (byte) 0x39,
                (byte) 0x01, (byte) 0x52, (byte) 0xd8, (byte) 0xfb, (byte) 0xb3, (byte) 0xf2, (byte) 0x03, (byte) 0x27,
                (byte) 0xd8, (byte) 0x24, (byte) 0xb2, (byte) 0x84, (byte) 0xd2, (byte) 0x88, (byte) 0xfb, (byte) 0x01,
                (byte) 0x52, (byte) 0xe4, (byte) 0x9f, (byte) 0xc4, (byte) 0x46, (byte) 0x78, (byte) 0xae, (byte) 0xd4,
                (byte) 0xd3, (byte) 0xf0, (byte) 0x85, (byte) 0xb7, (byte) 0xc5, (byte) 0x5d, (byte) 0xe7, (byte) 0x7b,
                (byte) 0xd4, (byte) 0x5a, (byte) 0xf8, (byte) 0x12, (byte) 0xfc, (byte) 0x37, (byte) 0x94, (byte) 0x4a,
                (byte) 0xd2, (byte) 0x45, (byte) 0x4f, (byte) 0x99, (byte) 0xfb, (byte) 0xb3, (byte) 0x4a, (byte) 0x58,
                (byte) 0x3b, (byte) 0xf1, (byte) 0x6b, (byte) 0x67, (byte) 0x65, (byte) 0x9e, (byte) 0x6f, (byte) 0x21,
                (byte) 0x6d, (byte) 0x34, (byte) 0xb1, (byte) 0xd7, (byte) 0x9b, (byte) 0x1b, (byte) 0x4d, (byte) 0xec,
                (byte) 0xc0, (byte) 0x98, (byte) 0xa4, (byte) 0x42, (byte) 0x07, (byte) 0xe1, (byte) 0xc5, (byte) 0xfe,
                (byte) 0xeb, (byte) 0x6c, (byte) 0xe3, (byte) 0x0a, (byte) 0xcc, (byte) 0x2c, (byte) 0xf7, (byte) 0xe2,
                (byte) 0xb1, (byte) 0x34, (byte) 0x49, (byte) 0x0b, (byte) 0x44, (byte) 0x27, (byte) 0x44, (byte) 0x77,
                (byte) 0x2d, (byte) 0x18, (byte) 0x4e, (byte) 0x59, (byte) 0x03, (byte) 0x8a, (byte) 0xa5, (byte) 0x17,
                (byte) 0xa9, (byte) 0x71, (byte) 0x54, (byte) 0x18, (byte) 0x1e, (byte) 0x4d, (byte) 0xfd, (byte) 0x94,
                (byte) 0xfe, (byte) 0x72, (byte) 0xa5, (byte) 0xa4, (byte) 0xca, (byte) 0x2e, (byte) 0x7e, (byte) 0x22,
                (byte) 0xbc, (byte) 0xe7, (byte) 0x33, (byte) 0xd0, (byte) 0x3e, (byte) 0x7d, (byte) 0x93, (byte) 0x19,
                (byte) 0x71, (byte) 0x0b, (byte) 0xef, (byte) 0xbc, (byte) 0x30, (byte) 0xd7, (byte) 0x82, (byte) 0x6b,
                (byte) 0x72, (byte) 0x85, (byte) 0x19, (byte) 0xba, (byte) 0x74, (byte) 0x69, (byte) 0x0e, (byte) 0x4f,
                (byte) 0x90, (byte) 0x65, (byte) 0x87, (byte) 0xa0, (byte) 0x38, (byte) 0x28, (byte) 0x95, (byte) 0xb9,
                (byte) 0x0d, (byte) 0x82, (byte) 0xed, (byte) 0x3e, (byte) 0x35, (byte) 0x7f, (byte) 0xaf, (byte) 0x8e,
                (byte) 0x59, (byte) 0xac, (byte) 0xa8, (byte) 0x5f, (byte) 0xd2, (byte) 0x06, (byte) 0x3a, (byte) 0xb5,
                (byte) 0x92, (byte) 0xd8, (byte) 0x3d, (byte) 0x24, (byte) 0x5a, (byte) 0x91, (byte) 0x9e, (byte) 0xa5,
                (byte) 0x3c, (byte) 0x50, (byte) 0x1b, (byte) 0x9a, (byte) 0xcc, (byte) 0xd2, (byte) 0xa1, (byte) 0xed,
                (byte) 0x95, (byte) 0x1f, (byte) 0x43, (byte) 0xc0, (byte) 0x49, (byte) 0xab, (byte) 0x9d, (byte) 0x25,
                (byte) 0xc7, (byte) 0xf1, (byte) 0xb7, (byte) 0x0a, (byte) 0xe4, (byte) 0xf9, (byte) 0x42, (byte) 0xed,
                (byte) 0xb1, (byte) 0xf3, (byte) 0x11, (byte) 0xf7, (byte) 0x41, (byte) 0x78, (byte) 0x33, (byte) 0x06,
                (byte) 0x22, (byte) 0x45, (byte) 0xb4, (byte) 0x29, (byte) 0xd4, (byte) 0xf0, (byte) 0x13, (byte) 0xae,
                (byte) 0x90, (byte) 0x19, (byte) 0xff, (byte) 0x52, (byte) 0x04, (byte) 0x4c, (byte) 0x97, (byte) 0xc7,
                (byte) 0x3b, (byte) 0x88, (byte) 0x82, (byte) 0xcf, (byte) 0x03, (byte) 0x95, (byte) 0x5c, (byte) 0x73,
                (byte) 0x9f, (byte) 0x87, (byte) 0x4a, (byte) 0x02, (byte) 0x96, (byte) 0x37, (byte) 0xc0, (byte) 0xf0,
                (byte) 0x60, (byte) 0x71, (byte) 0x00, (byte) 0xe3, (byte) 0x07, (byte) 0x0f, (byte) 0x40, (byte) 0x8d,
                (byte) 0x08, (byte) 0x2a, (byte) 0xa7, (byte) 0xa2, (byte) 0xab, (byte) 0xf1, (byte) 0x3e, (byte) 0x73,
                (byte) 0xbd, (byte) 0x1e, (byte) 0x25, (byte) 0x2c, (byte) 0x22, (byte) 0x8a, (byte) 0xba, (byte) 0x7a,
                (byte) 0x9c, (byte) 0x1f, (byte) 0x07, (byte) 0x5b, (byte) 0xc4, (byte) 0x39, (byte) 0x57, (byte) 0x1b,
                (byte) 0x35, (byte) 0x93, (byte) 0x2f, (byte) 0x5c, (byte) 0x91, (byte) 0x2c, (byte) 0xb0, (byte) 0xb3,
                (byte) 0x8d, (byte) 0xa1, (byte) 0xc9, (byte) 0x5e, (byte) 0x64, (byte) 0xfc, (byte) 0xf9, (byte) 0xbf,
                (byte) 0xec, (byte) 0x0b, (byte) 0x9b, (byte) 0x0d, (byte) 0xd8, (byte) 0xf0, (byte) 0x42, (byte) 0xfd,
                (byte) 0xf0, (byte) 0x5e, (byte) 0x50, (byte) 0x58, (byte) 0x29, (byte) 0x9e, (byte) 0x96, (byte) 0xe4,
                (byte) 0x18, (byte) 0x50, (byte) 0x74, (byte) 0x91, (byte) 0x9d, (byte) 0x90, (byte) 0xb7, (byte) 0xb3,
                (byte) 0xb0, (byte) 0xa9, (byte) 0x7e, (byte) 0x22, (byte) 0x42, (byte) 0xca, (byte) 0x08, (byte) 0xcd,
                (byte) 0x99, (byte) 0xc9, (byte) 0xec, (byte) 0xb1, (byte) 0x2f, (byte) 0xc4, (byte) 0x9a, (byte) 0xdb,
                (byte) 0x2b, (byte) 0x25, (byte) 0x72, (byte) 0x40, (byte) 0xcc, (byte) 0x38, (byte) 0x78, (byte) 0x02,
                (byte) 0xf0, (byte) 0x0e, (byte) 0x0e, (byte) 0x49, (byte) 0x95, (byte) 0x26, (byte) 0x63, (byte) 0xea,
                (byte) 0x27, (byte) 0x84, (byte) 0x08, (byte) 0x70, (byte) 0x9b, (byte) 0xce, (byte) 0x5b, (byte) 0x36,
                (byte) 0x3c, (byte) 0x03, (byte) 0x60, (byte) 0x93, (byte) 0xd7, (byte) 0xa0, (byte) 0x5d, (byte) 0x44,
                (byte) 0x0c, (byte) 0x9e, (byte) 0x7a, (byte) 0x7a, (byte) 0xbb, (byte) 0x3d, (byte) 0x71, (byte) 0xeb,
                (byte) 0xb4, (byte) 0xd1, (byte) 0x0b, (byte) 0xfc, (byte) 0x77, (byte) 0x81, (byte) 0xbc, (byte) 0xd6,
                (byte) 0x6f, (byte) 0x79, (byte) 0x32, (byte) 0x2c, (byte) 0x18, (byte) 0x26, (byte) 0x2d, (byte) 0xfc,
                (byte) 0x2d, (byte) 0xcc, (byte) 0xf3, (byte) 0xe5, (byte) 0xf1, (byte) 0xea, (byte) 0x98, (byte) 0xbe,
                (byte) 0xa3, (byte) 0xca, (byte) 0xae, (byte) 0x8a, (byte) 0x83, (byte) 0x70, (byte) 0x63, (byte) 0x12,
                (byte) 0x76, (byte) 0x44, (byte) 0x23, (byte) 0xa6, (byte) 0x92, (byte) 0xae, (byte) 0x0c, (byte) 0x1e,
                (byte) 0x2e, (byte) 0x23, (byte) 0xb0, (byte) 0x16, (byte) 0x86, (byte) 0x5f, (byte) 0xfb, (byte) 0x12,
                (byte) 0x5b, (byte) 0x22, (byte) 0x38, (byte) 0x57, (byte) 0x54, (byte) 0x7a, (byte) 0xc7, (byte) 0xe2,
                (byte) 0x46, (byte) 0x84, (byte) 0x33, (byte) 0xb5, (byte) 0x26, (byte) 0x98, (byte) 0x43, (byte) 0xab,
                (byte) 0xba, (byte) 0xbb, (byte) 0xe9, (byte) 0xf6, (byte) 0xf4, (byte) 0x38, (byte) 0xd7, (byte) 0xe3,
                (byte) 0x87, (byte) 0xe3, (byte) 0x61, (byte) 0x7a, (byte) 0x21, (byte) 0x9f, (byte) 0x62, (byte) 0x54,
                (byte) 0x0e, (byte) 0x73, (byte) 0x43, (byte) 0xe1, (byte) 0xbb, (byte) 0xf4, (byte) 0x93, (byte) 0x55,
                (byte) 0xfb, (byte) 0x5a, (byte) 0x19, (byte) 0x38, (byte) 0x04, (byte) 0x84, (byte) 0x39, (byte) 0xcb,
                (byte) 0xa5, (byte) 0xce, (byte) 0xe8, (byte) 0x19, (byte) 0x19, (byte) 0x9b, (byte) 0x2b, (byte) 0x5c,
                (byte) 0x39, (byte) 0xfd, (byte) 0x35, (byte) 0x1a, (byte) 0xa2, (byte) 0x74, (byte) 0x53, (byte) 0x6a,
                (byte) 0xad, (byte) 0xb6, (byte) 0x82, (byte) 0xb5, (byte) 0x78, (byte) 0x94, (byte) 0x3f, (byte) 0x0c,
                (byte) 0xcf, (byte) 0x48, (byte) 0xe4, (byte) 0xec, (byte) 0x7d, (byte) 0xdc, (byte) 0x93, (byte) 0x8e,
                (byte) 0x2f, (byte) 0xd0, (byte) 0x1a, (byte) 0xcf, (byte) 0xaa, (byte) 0x1e, (byte) 0x72, (byte) 0x17,
                (byte) 0xf7, (byte) 0xb3, (byte) 0x89, (byte) 0x28, (byte) 0x5c, (byte) 0x0d, (byte) 0xfd, (byte) 0x31,
                (byte) 0xa1, (byte) 0x54, (byte) 0x5e, (byte) 0xd3, (byte) 0xa8, (byte) 0x5f, (byte) 0xac, (byte) 0x8e,
                (byte) 0xb9, (byte) 0xda, (byte) 0xb6, (byte) 0xee, (byte) 0x82, (byte) 0x6a, (byte) 0xf9, (byte) 0x0f,
                (byte) 0x9e, (byte) 0x1e, (byte) 0xe5, (byte) 0xd5, (byte) 0x55, (byte) 0xdd, (byte) 0x1c, (byte) 0x05,
                (byte) 0xae, (byte) 0xc0, (byte) 0x77, (byte) 0xf7, (byte) 0xc8, (byte) 0x03, (byte) 0xcb, (byte) 0xc2,
                (byte) 0xf1, (byte) 0xcf, (byte) 0x98, (byte) 0x39, (byte) 0x3f, (byte) 0x0f, (byte) 0x37, (byte) 0x83,
                (byte) 0x8f, (byte) 0xfe, (byte) 0xa3, (byte) 0x72, (byte) 0xff, (byte) 0x70, (byte) 0x88, (byte) 0x86,
                (byte) 0xb0, (byte) 0x59, (byte) 0x34, (byte) 0xe1, (byte) 0xa6, (byte) 0x45, (byte) 0x12, (byte) 0xde,
                (byte) 0x14, (byte) 0x46, (byte) 0x08, (byte) 0x86, (byte) 0x4a, (byte) 0x88, (byte) 0xa5, (byte) 0xc3,
                (byte) 0xa1, (byte) 0x73, (byte) 0xfd, (byte) 0xcf, (byte) 0xdf, (byte) 0x57, (byte) 0x25, (byte) 0xda,
                (byte) 0x91, (byte) 0x6e, (byte) 0xd5, (byte) 0x07, (byte) 0xe4, (byte) 0xca, (byte) 0xec, (byte) 0x87,
                (byte) 0x87, (byte) 0xbe, (byte) 0xfb, (byte) 0x91, (byte) 0xe3, (byte) 0xec, (byte) 0x9b, (byte) 0x22,
                (byte) 0x2f, (byte) 0xa0, (byte) 0x9f, (byte) 0x37, (byte) 0x4b, (byte) 0xd9, (byte) 0x68, (byte) 0x81,
                (byte) 0xac, (byte) 0x2d, (byte) 0xdd, (byte) 0x1f, (byte) 0x88, (byte) 0x5d, (byte) 0x42, (byte) 0xea,
                (byte) 0x58, (byte) 0x4c, (byte) 0xe0, (byte) 0x8b, (byte) 0x0e, (byte) 0x45, (byte) 0x5a, (byte) 0x35,
                (byte) 0x0a, (byte) 0xe5, (byte) 0x4d, (byte) 0x76, (byte) 0x34, (byte) 0x9a, (byte) 0xa6, (byte) 0x8c,
                (byte) 0x71, (byte) 0xae
        };


        int recordSize = (wrapper[3] & 0xff) << 8 | (wrapper[4] & 0xff);
        System.out.println("Wrapper length: " + wrapper.length + " bytes, record size: " + recordSize);

        byte[] recordHeader = new byte[5];
        byte[] encryptedData = new byte[recordSize - 16];
        byte[] authTag = new byte[16];
        System.arraycopy(wrapper, 0, recordHeader, 0, recordHeader.length);
        System.arraycopy(wrapper, 5, encryptedData, 0, encryptedData.length);
        System.arraycopy(wrapper, 5 + recordSize - 16, authTag, 0, authTag.length);

        byte[] message = new byte[recordSize];
        System.arraycopy(wrapper, 5, message, 0, message.length);

        System.out.println("Record data: " + bytesToHex(recordHeader));
        System.out.println("Encrypted data: " + bytesToHex(encryptedData, 8) + "..." + bytesToHex(encryptedData, encryptedData.length - 8, 8));
        System.out.println("Auth tag: " + bytesToHex(authTag));

        byte[] wrapped = decryptPayload(message, recordHeader, 0);
        System.out.println("Decrypted data (" + wrapped.length + "): " + bytesToHex(wrapped, 8) + "..." + bytesToHex(wrapped, wrapped.length - 8, 8));
        return wrapped;
    }

    static byte[] decryptPayload(byte[] message, byte[] associatedData, int recordNumber) throws Exception {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong((long) recordNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ serverHandshakeIV[i++]);

        SecretKeySpec secretKey = new SecretKeySpec(serverHandshakeKey, "AES");
        String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
        Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
        aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        aeadCipher.updateAAD(associatedData);
        return aeadCipher.doFinal(message);
    }

    private static void computeSecrets(byte[] helloHash, byte[] sharedSecret) throws Exception {
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] zeroSalt = new byte[32];
        byte[] zeroPSK = new byte[32];
        byte[] earlySecret = hkdf.extract(zeroSalt, zeroPSK);
        System.out.println("Early secret: " + bytesToHex(earlySecret));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] emptyHash = digest.digest(new byte[0]);
        System.out.println("Empty hash: " + bytesToHex(emptyHash));

        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, (short) 32);
        System.out.println("Derived secret: " + bytesToHex(derivedSecret));

        byte[] handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);
        System.out.println("Handshake secret: " + bytesToHex(handshakeSecret));

        byte[] clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloHash, (short) 32);
        System.out.println("Client handshake traffic secret: " + bytesToHex(clientHandshakeTrafficSecret));

        byte[] serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloHash, (short) 32);
        System.out.println("Server handshake traffic secret: " + bytesToHex(serverHandshakeTrafficSecret));

        byte[] clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", (short) 16);
        System.out.println("Client handshake key: " + bytesToHex(clientHandshakeKey));

        serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", (short) 16);
        System.out.println("Server handshake key: " + bytesToHex(serverHandshakeKey));

        byte[] clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", (short) 12);
        System.out.println("Client handshake iv: " + bytesToHex(clientHandshakeIV));

        serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", (short) 12);
        System.out.println("Server handshake iv: " + bytesToHex(serverHandshakeIV));
    }

    private static byte[] computeHandshakeMessagesHash()throws Exception {

        byte[] clientHello = new byte[] {
                (byte) 0x16, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0xca, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xc6, (byte) 0x03, (byte) 0x03, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0xe0, (byte) 0xe1, (byte) 0xe2, (byte) 0xe3, (byte) 0xe4, (byte) 0xe5, (byte) 0xe6, (byte) 0xe7, (byte) 0xe8, (byte) 0xe9, (byte) 0xea, (byte) 0xeb, (byte) 0xec, (byte) 0xed, (byte) 0xee, (byte) 0xef, (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff, (byte) 0x00, (byte) 0x06, (byte) 0x13, (byte) 0x01, (byte) 0x13, (byte) 0x02, (byte) 0x13, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x77, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x00, (byte) 0x13, (byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6d, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x75, (byte) 0x6c, (byte) 0x66, (byte) 0x68, (byte) 0x65, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x6e, (byte) 0x65, (byte) 0x74, (byte) 0x00, (byte) 0x0a, (byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x1d, (byte) 0x00, (byte) 0x17, (byte) 0x00, (byte) 0x18, (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x12, (byte) 0x04, (byte) 0x03, (byte) 0x08, (byte) 0x04, (byte) 0x04, (byte) 0x01, (byte) 0x05, (byte) 0x03, (byte) 0x08, (byte) 0x05, (byte) 0x05, (byte) 0x01, (byte) 0x08, (byte) 0x06, (byte) 0x06, (byte) 0x01, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x26, (byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x1d, (byte) 0x00, (byte) 0x20, (byte) 0x35, (byte) 0x80, (byte) 0x72, (byte) 0xd6, (byte) 0x36, (byte) 0x58, (byte) 0x80, (byte) 0xd1, (byte) 0xae, (byte) 0xea, (byte) 0x32, (byte) 0x9a, (byte) 0xdf, (byte) 0x91, (byte) 0x21, (byte) 0x38, (byte) 0x38, (byte) 0x51, (byte) 0xed, (byte) 0x21, (byte) 0xa2, (byte) 0x8e, (byte) 0x3b, (byte) 0x75, (byte) 0xe9, (byte) 0x65, (byte) 0xd0, (byte) 0xd2, (byte) 0xcd, (byte) 0x16, (byte) 0x62, (byte) 0x54, (byte) 0x00, (byte) 0x2d, (byte) 0x00, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x2b, (byte) 0x00, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x04
        };
        byte[] serverHello = new byte[] {
                (byte) 0x16, (byte) 0x03, (byte) 0x03, (byte) 0x00, (byte) 0x7a, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x76, (byte) 0x03, (byte) 0x03, (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75, (byte) 0x76, (byte) 0x77, (byte) 0x78, (byte) 0x79, (byte) 0x7a, (byte) 0x7b, (byte) 0x7c, (byte) 0x7d, (byte) 0x7e, (byte) 0x7f, (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f, (byte) 0x20, (byte) 0xe0, (byte) 0xe1, (byte) 0xe2, (byte) 0xe3, (byte) 0xe4, (byte) 0xe5, (byte) 0xe6, (byte) 0xe7, (byte) 0xe8, (byte) 0xe9, (byte) 0xea, (byte) 0xeb, (byte) 0xec, (byte) 0xed, (byte) 0xee, (byte) 0xef, (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff, (byte) 0x13, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x2e, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x1d, (byte) 0x00, (byte) 0x20, (byte) 0x9f, (byte) 0xd7, (byte) 0xad, (byte) 0x6d, (byte) 0xcf, (byte) 0xf4, (byte) 0x29, (byte) 0x8d, (byte) 0xd3, (byte) 0xf9, (byte) 0x6d, (byte) 0x5b, (byte) 0x1b, (byte) 0x2a, (byte) 0xf9, (byte) 0x10, (byte) 0xa0, (byte) 0x53, (byte) 0x5b, (byte) 0x14, (byte) 0x88, (byte) 0xd7, (byte) 0xf8, (byte) 0xfa, (byte) 0xbb, (byte) 0x34, (byte) 0x9a, (byte) 0x98, (byte) 0x28, (byte) 0x80, (byte) 0xb6, (byte) 0x15, (byte) 0x00, (byte) 0x2b, (byte) 0x00, (byte) 0x02, (byte) 0x03, (byte) 0x04
        };
        ByteBuffer helloData = ByteBuffer.allocate(clientHello.length - 5 + serverHello.length - 5);
        helloData.put(clientHello, 5, clientHello.length - 5);
        helloData.put(serverHello, 5, serverHello.length - 5);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] helloHash = digest.digest(helloData.array());

        System.out.println("Hello hash: " + bytesToHex(helloHash));
        return helloHash;
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        byte[] keyBytes = keyAgreement.generateSecret();
        System.out.println("shared secret: " + bytesToHex(keyBytes));
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        return key;
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] data, int offset, int length) {
        String digits = "0123456789abcdef";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[offset+i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789abcdef";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static PublicKey get(String filename) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("X25519", "BC");
        return kf.generatePublic(spec);
    }

    public static PrivateKey getPrivate(String filename) throws Exception {
        Security.addProvider(new BouncyCastleProvider());


        Reader rdr = new InputStreamReader(new FileInputStream(filename));
        Object parsed = new org.bouncycastle.openssl.PEMParser(rdr).readObject();
        KeyPair pair = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair)parsed);
        System.out.println (pair.getPrivate().getAlgorithm());
        return pair.getPrivate();
    }

    static byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + 6 + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (6 + label.getBytes().length));
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
        hkdfLabel.put("tls13 ".getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + 6 + label.getBytes(ISO_8859_1).length + 1 + context.length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (6 + label.getBytes().length));
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
        hkdfLabel.put("tls13 ".getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.length));
        hkdfLabel.put(context);
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

}
