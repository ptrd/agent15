/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.CertificateUtils;
import tech.kwik.agent15.alert.BadCertificateAlert;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertificateMessageTest {

    @Test
    void parseCertificateMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes(gmailCertificateMessageBytes);
        CertificateMessage cm = new CertificateMessage();
        cm.parse(ByteBuffer.wrap(rawData));
        assertThat(cm.getEndEntityCertificate()).isNotNull();
        assertThat(cm.getCertificateChain()).hasSizeGreaterThan(1);

        // Verify that certificate can be generated.
        List<Object> names = cm.getEndEntityCertificate().getSubjectAlternativeNames().stream()
                .flatMap(l -> Stream.of(l.get(1)))
                .collect(Collectors.toList());
        assertThat(names).contains("gmail.com");
    }

    @Test
    void parseNoMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b00");
        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseNotEnoughBytesForMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b000066");
        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseSingleCertificateMessage() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                // cert list size cert data size
                + "0004d6" +      "0004d1" + gmailCertificateBytes + "0000");
        CertificateMessage cm = new CertificateMessage().parse(ByteBuffer.wrap(rawData));
        assertThat(cm.getCertificateChain()).hasSize(1);
    }

    @Test
    void parseInvalidCertificate() throws Exception {
        byte[] bogusCert = new byte[1233];
        byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                // cert list size cert data size
                + "0004d6" +      "0004d1" + ByteUtils.bytesToHex(bogusCert) + "0000");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(BadCertificateAlert.class);
    }

    @Test
    void parseMessageWithoutCertificate() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b000009" + "00" + "000005" + "000000" + "0000");

        CertificateMessage cm = new CertificateMessage().parse(ByteBuffer.wrap(rawData));

        assertThat(cm.getCertificateChain()).hasSize(0);
    }

    @Test
    void parseCertificateMessageWithIncorrectCertificateRequestContextLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "ff"
                // cert list size cert data size
                + "0004d6" +      "000020" + "012345678901234567890123456789012345678901" + "0000");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseCertificateMessageWithIncorrectCertificateListLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "00"
                // cert list size cert data size
                + "0004d6" +      "000020" + "012345678901234567890123456789012345678901" + "0000");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseCertificateMessageWithIncorrectCertificateLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b00001d" + "00"
                // cert list size cert data size
                + "000024" +      "000020" + "0123456789012345678901234567890123456789" + "0000");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseCertificateMessageWithIncorrectCertificateExtensionLength() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                // cert list size cert data size
                + "0004d6" +      "0004d1" + gmailCertificateBytes + "00ff");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeCertificateMessage() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[300]);
        CertificateMessage certificateMessage = new CertificateMessage(cert);

        byte[] data = certificateMessage.getBytes();
        int messageLength = 4 + ByteBuffer.wrap(data).getInt() & 0x00ffffff;
        assertThat(data.length).isEqualTo(messageLength);

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(data)))
                .isInstanceOf(BadCertificateAlert.class);
    }

    @Test
    void serializeAndDeserializeCertificateMessage() throws Exception {
        X509Certificate cert = CertificateUtils.getTestCertificate();
        CertificateMessage certificateMessage = new CertificateMessage(cert);

        byte[] data = certificateMessage.getBytes();
        int messageLength = 4 + ByteBuffer.wrap(data).getInt() & 0x00ffffff;
        assertThat(data.length).isEqualTo(messageLength);

        CertificateMessage parsedCertificateMessage = new CertificateMessage().parse(ByteBuffer.wrap(data));
        assertThat(parsedCertificateMessage.getEndEntityCertificate()).isEqualTo(cert);
    }

    @Test
    void parseMessageWithVeryLargeExtensionSize() throws Exception {
        byte[] rawData = ByteUtils.hexToBytes("0b000400" + "00"
                // cert list size cert data size
                + "0004d6" +      "0004d1" + gmailCertificateBytes + "8000");

        assertThatThrownBy(() ->
                new CertificateMessage().parse(ByteBuffer.wrap(rawData))
        ).isInstanceOf(DecodeErrorException.class);
    }

    String gmailCertificateMessageBytes = "0b00092d000009290004d1308204cd308203b5a003020102021100a07defd2e6ff026c08"
            + "000000003ebf0d300d06092a864886f70d01010b05003042310b3009060355040613025553311e301c060355040a1315476f6f67"
            + "6c65205472757374205365727669636573311330110603550403130a47545320434120314f31301e170d32303035303530383336"
            + "31305a170d3230303732383038333631305a3063310b3009060355040613025553311330110603550408130a43616c69666f726e"
            + "6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433112301006"
            + "035504031309676d61696c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e47e42dfb934737833dd"
            + "b6e4507c2a7775f3f759b88dec3478e7dce3cc04ae42ab381472c7a7c27069b694299a905c33a6107ae7347ae43a34ae70f42eac"
            + "fbc0a382026630820262300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c060355"
            + "1d130101ff04023000301d0603551d0e04160414a841046aa9ccef3104c311cc69a9e7cdd40dc93d301f0603551d230418301680"
            + "1498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b306806082b06010505070101045c305a302b06082b06010505073001861f68"
            + "7474703a2f2f6f6373702e706b692e676f6f672f677473316f31636f7265302b06082b06010505073002861f687474703a2f2f70"
            + "6b692e676f6f672f677372322f475453314f312e63727430210603551d11041a30188209676d61696c2e636f6d820b2a2e676d61"
            + "696c2e636f6d30210603551d20041a30183008060667810c010202300c060a2b06010401d67902050330330603551d1f042c302a"
            + "3028a026a0248622687474703a2f2f63726c2e706b692e676f6f672f475453314f31636f72652e63726c30820106060a2b060104"
            + "01d6790204020481f70481f400f2007700b21e05cc8ba2cd8a204e8766f92bb98a2520676bdafa70e7b249532def8b905e000001"
            + "71e43155ad0000040300483046022100d6815e996faf6cde205f674ef2356b0350291e0e68ed5aaa9cb3282ac5fd825e022100b7"
            + "c39d624386e538f2dc3bdb31e0d1206d4a1fb3d0a660bfbc3b17680f5633320077005ea773f9df56c0e7b536487dd049e0327a91"
            + "9a0c84a11212841875968171455800000171e43155ae0000040300483046022100c72bde3052e0a20a2c88df3cbd4f83e94513dd"
            + "a41f924b324e13e105360c5b57022100c2cdf5111cda53c29080f39f73450dce6284d0f2c46dde483d589be62ac3565a300d0609"
            + "2a864886f70d01010b050003820101002f475e22cb4ea5b4c049abf0593a6be7cefc91901bb8cce91bb2abfe651427324472fb66"
            + "39f46e7b20cfb6626a9605fd2d56d1aa1b058b752dfcad326a219f30001f72b43ed6d0c3e162b7cd7bf82eb92ed7e79e2fc51e61"
            + "0953907549a6361dd1f9a6e01da1a6ec4ad786fc469b1c0fccfc695a4ff6566597a3ade8fe051df463e7a6fd5a14021caeb218ff"
            + "4b2bfe049bf30ab69d432ee85a15bcba47f2d584e9c22665ad24bcf487aff3f6328bd60bcac5354c5306d6b299d98cc1bf52de4b"
            + "5b079df2578f512476ca58bb8067287baff654ca1a1e161703befbf50be5a2911551c86483bd893fb9f630e8fc3339e105d06689"
            + "aa670e484d076c322eb1eda9000000044e3082044a30820332a003020102020d01e3b49aa18d8aa981256950b8300d06092a8648"
            + "86f70d01010b0500304c3120301e060355040b1317476c6f62616c5369676e20526f6f74204341202d2052323113301106035504"
            + "0a130a476c6f62616c5369676e311330110603550403130a476c6f62616c5369676e301e170d3137303631353030303034325a17"
            + "0d3231313231353030303034325a3042310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374"
            + "205365727669636573311330110603550403130a47545320434120314f3130820122300d06092a864886f70d0101010500038201"
            + "0f003082010a0282010100d018cf45d48bcdd39ce440ef7eb4dd69211bc9cf3c8e4c75b90f3119843d9e3c29ef500d10936f0580"
            + "809f2aa0bd124b02e13d9f581624fe309f0b747755931d4bf74de1928210f651ac0cc3b222940f346b981049e70b9d8339dd20c6"
            + "1c2defd1186165e7238320a82312ffd2247fd42fe7446a5b4dd75066b0af9e426305fbe01cc46361af9f6a33ff6297bd48d9d37c"
            + "1467dc75dc2e69e8f86d7869d0b71005b8f131c23b24fd1a3374f823e0ec6b198a16c6e3cda4cd0bdbb3a4596038883bad1db9c6"
            + "8ca7531bfcbcd9a4abbcdd3c61d7931598ee81bd8fe264472040064ed7ac97e8b9c05912a1492523e4ed70342ca5b4637cf9a33d"
            + "83d1cd6d24ac070203010001a38201333082012f300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601"
            + "050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e0416041498d1f86e10eb"
            + "cf9bec609f18901ba0eb7d09fd2b301f0603551d230418301680149be20757671c1ec06a06de59b49a2ddfdc19862e303506082b"
            + "0601050507010104293027302506082b060105050730018619687474703a2f2f6f6373702e706b692e676f6f672f677372323032"
            + "0603551d1f042b30293027a025a0238621687474703a2f2f63726c2e706b692e676f6f672f677372322f677372322e63726c303f"
            + "0603551d20043830363034060667810c010202302a302806082b06010505070201161c68747470733a2f2f706b692e676f6f672f"
            + "7265706f7369746f72792f300d06092a864886f70d01010b050003820101001a803e3679fbf32ea946377d5e541635aec74e0899"
            + "febdd13469265266073d0aba49cb62f4f11a8efc114f68964c742bd367deb2a3aa058d844d4c20650fa596da0d16f86c3bdb6f04"
            + "23886b3a6cc160bd689f718eee2d583407f0d554e98659fd7b5e0d2194f58cc9a8f8d8f2adcc0f1af39aa7a90427f9a3c9b0ff02"
            + "786b61bac7352be856fa4fc31c0cedb63cb44beaedcce13cecdc0d8cd63e9bca42588bcc16211740bca2d666efdac4155bcd89aa"
            + "9b0926e732d20d6e6720025b10b090099c0c1f9eadd83beaa1fc6ce8105c085219512a71bbac7ab5dd15ed2bc9082a2c8ab4a621"
            + "ab63ffd7524950d089b7adf2affb50ae2fe1950df346ad9d9cf5ca0000";

    String gmailCertificateBytes = "308204cd308203b5a003020102021100a07defd2e6ff026c08"
            + "000000003ebf0d300d06092a864886f70d01010b05003042310b3009060355040613025553311e301c060355040a1315476f6f67"
            + "6c65205472757374205365727669636573311330110603550403130a47545320434120314f31301e170d32303035303530383336"
            + "31305a170d3230303732383038333631305a3063310b3009060355040613025553311330110603550408130a43616c69666f726e"
            + "6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433112301006"
            + "035504031309676d61696c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e47e42dfb934737833dd"
            + "b6e4507c2a7775f3f759b88dec3478e7dce3cc04ae42ab381472c7a7c27069b694299a905c33a6107ae7347ae43a34ae70f42eac"
            + "fbc0a382026630820262300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c060355"
            + "1d130101ff04023000301d0603551d0e04160414a841046aa9ccef3104c311cc69a9e7cdd40dc93d301f0603551d230418301680"
            + "1498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b306806082b06010505070101045c305a302b06082b06010505073001861f68"
            + "7474703a2f2f6f6373702e706b692e676f6f672f677473316f31636f7265302b06082b06010505073002861f687474703a2f2f70"
            + "6b692e676f6f672f677372322f475453314f312e63727430210603551d11041a30188209676d61696c2e636f6d820b2a2e676d61"
            + "696c2e636f6d30210603551d20041a30183008060667810c010202300c060a2b06010401d67902050330330603551d1f042c302a"
            + "3028a026a0248622687474703a2f2f63726c2e706b692e676f6f672f475453314f31636f72652e63726c30820106060a2b060104"
            + "01d6790204020481f70481f400f2007700b21e05cc8ba2cd8a204e8766f92bb98a2520676bdafa70e7b249532def8b905e000001"
            + "71e43155ad0000040300483046022100d6815e996faf6cde205f674ef2356b0350291e0e68ed5aaa9cb3282ac5fd825e022100b7"
            + "c39d624386e538f2dc3bdb31e0d1206d4a1fb3d0a660bfbc3b17680f5633320077005ea773f9df56c0e7b536487dd049e0327a91"
            + "9a0c84a11212841875968171455800000171e43155ae0000040300483046022100c72bde3052e0a20a2c88df3cbd4f83e94513dd"
            + "a41f924b324e13e105360c5b57022100c2cdf5111cda53c29080f39f73450dce6284d0f2c46dde483d589be62ac3565a300d0609"
            + "2a864886f70d01010b050003820101002f475e22cb4ea5b4c049abf0593a6be7cefc91901bb8cce91bb2abfe651427324472fb66"
            + "39f46e7b20cfb6626a9605fd2d56d1aa1b058b752dfcad326a219f30001f72b43ed6d0c3e162b7cd7bf82eb92ed7e79e2fc51e61"
            + "0953907549a6361dd1f9a6e01da1a6ec4ad786fc469b1c0fccfc695a4ff6566597a3ade8fe051df463e7a6fd5a14021caeb218ff"
            + "4b2bfe049bf30ab69d432ee85a15bcba47f2d584e9c22665ad24bcf487aff3f6328bd60bcac5354c5306d6b299d98cc1bf52de4b"
            + "5b079df2578f512476ca58bb8067287baff654ca1a1e161703befbf50be5a2911551c86483bd893fb9f630e8fc3339e105d06689"
            + "aa670e484d076c322eb1eda9";

}
