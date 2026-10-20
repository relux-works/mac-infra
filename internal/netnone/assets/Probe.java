import java.net.*;
import java.util.concurrent.*;

class Probe {
    public static void main(String[] args) {
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r); t.setDaemon(true); return t;
        });
        try {
            executor.submit(() -> InetAddress.getByName("repo.maven.apache.org")).get(5, TimeUnit.SECONDS);
            System.out.println("dns=ok");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            System.out.println("dns=fail:" + cause.getClass().getName());
        } finally {
            executor.shutdownNow();
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("1.1.1.1", 443), 5000);
            System.out.println("tcp=ok");
        } catch (Exception e) {
            String message = String.valueOf(e.getMessage()).replace('\n', ' ').replace('\r', ' ');
            System.out.println("tcp=fail:" + e.getClass().getName() + ":" + message);
        }
    }
}
