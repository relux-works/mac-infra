import java.net.*;
import java.io.*;
import java.nio.file.*;
import java.util.concurrent.*;

class Probe {
    public static void main(String[] args) {
        System.out.println("arch=" + System.getProperty("os.arch"));
        try (InputStream in = Files.newInputStream(Path.of("/proc/self/exe"))) {
            byte[] header = in.readNBytes(20);
            if (header.length != 20) throw new IOException("short ELF header");
            int machine = Byte.toUnsignedInt(header[18]) | (Byte.toUnsignedInt(header[19]) << 8);
            System.out.println("elf=" + machine);
        } catch (IOException e) {
            System.out.println("elf=unavailable");
        }
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
