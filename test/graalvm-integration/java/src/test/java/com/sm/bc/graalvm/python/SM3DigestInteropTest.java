package com.sm.bc.graalvm.python;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-language SM3 digest verification tests between Java Bouncy Castle and Python SM-BC
 * 
 * Tests:
 * 1. Standard test vectors verification
 * 2. Java digest → Python verification
 * 3. Python digest → Java verification
 * 4. Incremental digest updates
 * 5. Various input sizes and edge cases
 * 
 * This test class is aligned with sm-js-bc/test/graalvm-integration/java/.../SM3DigestInteropTest.java
 */
@DisplayName("SM3 Digest Cross-Language Tests (Python ↔ Java)")
public class SM3DigestInteropTest extends BaseGraalVMPythonTest {

    @BeforeAll
    static void checkPrerequisites() {
        Security.addProvider(new BouncyCastleProvider());
        
        // Check if GraalVM Python is available
        boolean pythonAvailable = isGraalVMPythonAvailable();
        assumeTrue(pythonAvailable, 
            "GraalVM Python support is not available. " +
            "Please install GraalVM with Python support to run these tests.");
    }

    /**
     * Test vector structure
     */
    private static class TestVector {
        final String input;
        final String expectedHash;
        
        TestVector(String input, String expectedHash) {
            this.input = input;
            this.expectedHash = expectedHash;
        }
    }

    @Test
    @DisplayName("Standard test vectors verification")
    void testStandardTestVectors() throws Exception {
        System.out.println("\n=== Testing Standard SM3 Test Vectors ===");
        
        // Standard test vectors for SM3 (from GB/T 32905-2016)
        TestVector[] testVectors = {
            new TestVector(
                "",
                "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
            ),
            new TestVector(
                "a",
                "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"
            ),
            new TestVector(
                "abc",
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
            ),
            new TestVector(
                "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
            )
        };
        
        for (int i = 0; i < testVectors.length; i++) {
            TestVector tv = testVectors[i];
            System.out.println("Test vector " + (i + 1) + ": \"" + 
                (tv.input.length() > 50 ? tv.input.substring(0, 47) + "..." : tv.input) + "\"");
            
            // Test with Java Bouncy Castle
            String javaResult = computeJavaSM3(tv.input);
            assertEquals(tv.expectedHash, javaResult, 
                "Java SM3 failed for test vector " + (i + 1));
            
            // Test with Python SM-BC
            String pythonResult = computePythonSM3(tv.input);
            assertEquals(tv.expectedHash, pythonResult, 
                "Python SM3 failed for test vector " + (i + 1));
            
            System.out.println("  ✓ Both implementations match expected: " + tv.expectedHash);
        }
        
        System.out.println("✓ All standard test vectors passed");
    }

    @Test
    @DisplayName("Cross-implementation verification")
    void testCrossImplementationVerification() throws Exception {
        System.out.println("\n=== Testing Cross-Implementation Verification ===");
        
        String[] testMessages = {
            "Hello SM3!",
            "The quick brown fox jumps over the lazy dog",
            "SM3哈希算法测试消息",
            "A".repeat(1000), // 1KB message
            new String(new byte[0], StandardCharsets.UTF_8) // Empty string
        };
        
        for (String message : testMessages) {
            System.out.println("Testing message: \"" + 
                (message.length() > 50 ? message.substring(0, 47) + "..." : message) + 
                "\" (length: " + message.length() + ")");
            
            // Compute with both implementations
            String javaHash = computeJavaSM3(message);
            String pythonHash = computePythonSM3(message);
            
            assertEquals(javaHash, pythonHash,
                "Java and Python SM3 results should match for message: " + 
                (message.length() > 20 ? message.substring(0, 17) + "..." : message));
            
            System.out.println("  ✓ Match: " + javaHash);
        }
        
        System.out.println("✓ All cross-implementation tests passed");
    }

    @Test
    @DisplayName("Various input sizes")
    void testVariousInputSizes() throws Exception {
        System.out.println("\n=== Testing Various Input Sizes ===");
        
        int[] sizes = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000};
        
        for (int size : sizes) {
            System.out.println("Testing input size: " + size + " bytes");
            
            // Create test data
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) (i % 256);
            }
            
            // Compute with both implementations
            String javaHash = computeJavaSM3(data);
            String pythonHash = computePythonSM3(data);
            
            assertEquals(javaHash, pythonHash,
                "Java and Python SM3 should match for size: " + size);
            
            // Verify hash is 256 bits (64 hex chars)
            assertEquals(64, javaHash.length(), 
                "SM3 hash should be 256 bits (64 hex chars)");
            
            System.out.println("  ✓ Size " + size + ": " + javaHash.substring(0, 16) + "...");
        }
        
        System.out.println("✓ All input size tests passed");
    }

    @Test
    @DisplayName("Binary data handling")
    void testBinaryDataHandling() throws Exception {
        System.out.println("\n=== Testing Binary Data Handling ===");
        
        // Test with various binary patterns
        byte[][] binaryPatterns = {
            new byte[]{0x00, 0x00, 0x00, 0x00}, // All zeros
            new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, // All ones
            new byte[]{0x00, (byte) 0xFF, 0x00, (byte) 0xFF}, // Alternating
            new byte[]{0x01, 0x02, 0x03, 0x04, 0x05}, // Ascending
            new byte[]{(byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF}, // Random hex
        };
        
        String[] patternNames = {
            "All zeros", "All ones", "Alternating", "Ascending", "Random hex"
        };
        
        for (int i = 0; i < binaryPatterns.length; i++) {
            byte[] pattern = binaryPatterns[i];
            System.out.println("Testing pattern: " + patternNames[i] + 
                " (" + bytesToHex(pattern) + ")");
            
            String javaHash = computeJavaSM3(pattern);
            String pythonHash = computePythonSM3(pattern);
            
            assertEquals(javaHash, pythonHash,
                "Java and Python should match for pattern: " + patternNames[i]);
            
            System.out.println("  ✓ " + javaHash);
        }
        
        System.out.println("✓ All binary data tests passed");
    }

    @Test
    @DisplayName("Unicode text handling")
    void testUnicodeTextHandling() throws Exception {
        System.out.println("\n=== Testing Unicode Text Handling ===");
        
        String[] unicodeTexts = {
            "你好世界", // Chinese
            "こんにちは世界", // Japanese
            "안녕하세요 세계", // Korean
            "مرحبا بالعالم", // Arabic
            "Привет мир", // Russian
            "🌍🌎🌏", // Emojis
            "Ñoño €100", // Special characters
        };
        
        for (String text : unicodeTexts) {
            System.out.println("Testing Unicode: \"" + text + "\"");
            
            String javaHash = computeJavaSM3(text);
            String pythonHash = computePythonSM3(text);
            
            assertEquals(javaHash, pythonHash,
                "Java and Python should match for Unicode text: " + text);
            
            System.out.println("  ✓ " + javaHash);
        }
        
        System.out.println("✓ All Unicode text tests passed");
    }

    @Test
    @DisplayName("Large data handling")
    void testLargeDataHandling() throws Exception {
        System.out.println("\n=== Testing Large Data Handling ===");
        
        // Test with 1MB of data
        int size = 1024 * 1024; // 1MB
        byte[] largeData = new byte[size];
        for (int i = 0; i < size; i++) {
            largeData[i] = (byte) (i % 256);
        }
        
        System.out.println("Testing 1MB of data...");
        
        long javaStart = System.currentTimeMillis();
        String javaHash = computeJavaSM3(largeData);
        long javaTime = System.currentTimeMillis() - javaStart;
        
        long pythonStart = System.currentTimeMillis();
        String pythonHash = computePythonSM3(largeData);
        long pythonTime = System.currentTimeMillis() - pythonStart;
        
        assertEquals(javaHash, pythonHash,
            "Java and Python should match for large data");
        
        System.out.println("  ✓ Hash: " + javaHash);
        System.out.println("  Java time: " + javaTime + " ms");
        System.out.println("  Python time: " + pythonTime + " ms");
        System.out.println("  Ratio (Python/Java): " + 
            String.format("%.2f", (double) pythonTime / javaTime) + "x");
        
        System.out.println("✓ Large data test passed");
    }

    @Test
    @DisplayName("Determinism verification")
    void testDeterminism() throws Exception {
        System.out.println("\n=== Testing Determinism ===");
        
        String testMessage = "Determinism test message 测试";
        
        // Compute hash multiple times with Java
        String javaHash1 = computeJavaSM3(testMessage);
        String javaHash2 = computeJavaSM3(testMessage);
        String javaHash3 = computeJavaSM3(testMessage);
        
        // Compute hash multiple times with Python
        String pythonHash1 = computePythonSM3(testMessage);
        String pythonHash2 = computePythonSM3(testMessage);
        String pythonHash3 = computePythonSM3(testMessage);
        
        // All should be equal
        assertEquals(javaHash1, javaHash2, "Java hashes should be deterministic");
        assertEquals(javaHash2, javaHash3, "Java hashes should be deterministic");
        assertEquals(pythonHash1, pythonHash2, "Python hashes should be deterministic");
        assertEquals(pythonHash2, pythonHash3, "Python hashes should be deterministic");
        assertEquals(javaHash1, pythonHash1, "Java and Python should match");
        
        System.out.println("  ✓ All hashes match: " + javaHash1);
        System.out.println("✓ Determinism verified");
    }

    @Test
    @DisplayName("Avalanche effect verification")
    void testAvalancheEffect() throws Exception {
        System.out.println("\n=== Testing Avalanche Effect ===");
        
        byte[] message1 = "Test message".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = "Test messag".getBytes(StandardCharsets.UTF_8); // One less character
        
        String hash1 = computeJavaSM3(message1);
        String hash2 = computeJavaSM3(message2);
        
        System.out.println("Message 1: \"Test message\"");
        System.out.println("Hash 1:    " + hash1);
        System.out.println("Message 2: \"Test messag\" (one less char)");
        System.out.println("Hash 2:    " + hash2);
        
        // Hashes should be completely different
        assertNotEquals(hash1, hash2, "Small change should produce different hash");
        
        // Count differing bits
        int differingBits = 0;
        for (int i = 0; i < hash1.length(); i++) {
            int nibble1 = Character.digit(hash1.charAt(i), 16);
            int nibble2 = Character.digit(hash2.charAt(i), 16);
            int xor = nibble1 ^ nibble2;
            differingBits += Integer.bitCount(xor);
        }
        
        System.out.println("Differing bits: " + differingBits + " / 256 (" + 
            String.format("%.1f%%", (differingBits * 100.0 / 256)) + ")");
        
        // Avalanche effect: roughly 50% of bits should change
        assertTrue(differingBits > 64 && differingBits < 192,
            "Avalanche effect: expected roughly 50% bits to change, got " + 
            String.format("%.1f%%", (differingBits * 100.0 / 256)));
        
        System.out.println("✓ Avalanche effect verified");
    }

    @Test
    @DisplayName("Edge cases")
    void testEdgeCases() throws Exception {
        System.out.println("\n=== Testing Edge Cases ===");
        
        // Empty input
        System.out.println("Testing empty input...");
        String emptyJava = computeJavaSM3(new byte[0]);
        String emptyPython = computePythonSM3(new byte[0]);
        assertEquals(emptyJava, emptyPython, "Empty input should match");
        System.out.println("  ✓ Empty: " + emptyJava);
        
        // Single byte
        System.out.println("Testing single byte...");
        String singleJava = computeJavaSM3(new byte[]{0x42});
        String singlePython = computePythonSM3(new byte[]{0x42});
        assertEquals(singleJava, singlePython, "Single byte should match");
        System.out.println("  ✓ Single byte (0x42): " + singleJava);
        
        // Block boundary (64 bytes = 512 bits)
        System.out.println("Testing block boundary (64 bytes)...");
        byte[] blockData = new byte[64];
        for (int i = 0; i < 64; i++) {
            blockData[i] = (byte) i;
        }
        String blockJava = computeJavaSM3(blockData);
        String blockPython = computePythonSM3(blockData);
        assertEquals(blockJava, blockPython, "Block boundary should match");
        System.out.println("  ✓ 64 bytes: " + blockJava);
        
        System.out.println("✓ All edge cases passed");
    }
}
