import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

class Download {
    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(Path.of(args[0]))) { properties.load(in); }
        Path target = Path.of(args[1]);
        URLConnection connection = URI.create(properties.getProperty("distributionUrl")).toURL().openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        try (InputStream in = connection.getInputStream()) { Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING); }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(target)) {
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) != -1) { digest.update(buffer, 0, n); }
        }
        String actual = HexFormat.of().formatHex(digest.digest());
        if (!actual.equals(properties.getProperty("distributionSha256Sum"))) {
            Files.delete(target);
            throw new SecurityException("Gradle distribution SHA-256 mismatch");
        }
    }
}
