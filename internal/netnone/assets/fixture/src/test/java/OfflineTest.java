import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class OfflineTest {
    @Test void arithmetic() { assertEquals(2, 1 + 1); }

    // Compiling this test requires the source package named build to survive copying.
    @Test void buildPackageWasCopied() { assertEquals(42, build.Marker.value()); }
}
