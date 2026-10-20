import java.net.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class NetworkTest {
    @Test void repositoryReachable() throws Exception {
        HttpURLConnection connection = (HttpURLConnection) URI.create("https://repo.maven.apache.org/maven2/").toURL().openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        try { assertEquals(200, connection.getResponseCode()); }
        finally { connection.disconnect(); }
    }
}
