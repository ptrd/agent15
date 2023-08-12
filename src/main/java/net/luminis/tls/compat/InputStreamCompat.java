package net.luminis.tls.compat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class InputStreamCompat {

    public static byte[] readAllBytes(InputStream in) throws IOException{
        byte[] buf = new byte[8192];
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int bytesRead;

        while((bytesRead = in.read(buf)) != -1) {
            bout.write(buf, 0, bytesRead);
        }
        bout.flush();

        return bout.toByteArray();
    }

}
