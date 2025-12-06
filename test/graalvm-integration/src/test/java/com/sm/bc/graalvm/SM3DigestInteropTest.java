package com.sm.bc.graalvm;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-language SM3 digest interoperability tests
 * Validates Python ↔ Java consistency
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SM3DigestInteropTest extends BaseGraalVMTest {
    
    @BeforeEach
    @Override
    public void setupGraalVM() {
        Assumptions.assumeTrue(isGraalVMPythonAvailable(),
                "GraalVM Python support not available - skipping test");
        super.setupGraalVM();
    }
    
    @Test
    @Order(1)
    @DisplayName("Empty string - Python and Java should produce same hash")
    public void testEmptyString() {
        byte[] input = new byte[0];
        
        String javaHash = computeJavaSM3(input);
        String pythonHash = computePythonSM3(input);
        
        System.out.println("=== SM3 Empty String Test ===");
        System.out.println("Java hash:   " + javaHash);
        System.out.println("Python hash: " + pythonHash);
        
        assertEquals(javaHash, pythonHash, "Python and Java SM3 hashes should match for empty input");
        assertEquals("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", 
                    javaHash.toLowerCase(), "Should match standard SM3 empty string hash");
    }
    
    @Test
    @Order(2)
    @DisplayName("Standard test vector 'abc' - Cross-platform verification")
    public void testStandardVector() {
        byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        
        String javaHash = computeJavaSM3(input);
        String pythonHash = computePythonSM3(input);
        
        System.out.println("\n=== SM3 Standard Vector Test ('abc') ===");
        System.out.println("Java hash:   " + javaHash);
        System.out.println("Python hash: " + pythonHash);
        
        assertEquals(javaHash, pythonHash, "Python and Java SM3 hashes should match");
        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                    javaHash.toLowerCase(), "Should match standard SM3 hash for 'abc'");
    }
    
    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "The quick brown fox jumps over the lazy dog"
    })
    @DisplayName("Various inputs - Python and Java consistency")
    public void testVariousInputs(String input) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        
        String javaHash = computeJavaSM3(inputBytes);
        String pythonHash = computePythonSM3(inputBytes);
        
        assertEquals(javaHash, pythonHash, 
                    "Python and Java SM3 hashes should match for input: " + 
                    (input.length() > 20 ? input.substring(0, 20) + "..." : input));
    }
    
    @Test
    @Order(3)
    @DisplayName("Large input (10KB) - Performance and consistency")
    public void testLargeInput() {
        // Create 10KB input
        byte[] input = new byte[10240];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) (i % 256);
        }
        
        long javaStart = System.currentTimeMillis();
        String javaHash = computeJavaSM3(input);
        long javaTime = System.currentTimeMillis() - javaStart;
        
        long pythonStart = System.currentTimeMillis();
        String pythonHash = computePythonSM3(input);
        long pythonTime = System.currentTimeMillis() - pythonStart;
        
        System.out.println("\n=== SM3 Large Input Test (10KB) ===");
        System.out.println("Java time:   " + javaTime + " ms");
        System.out.println("Python time: " + pythonTime + " ms");
        System.out.println("Java hash:   " + javaHash);
        System.out.println("Python hash: " + pythonHash);
        
        assertEquals(javaHash, pythonHash, "Python and Java SM3 hashes should match for large input");
    }
    
    @Test
    @Order(4)
    @DisplayName("Binary data - Various byte patterns")
    public void testBinaryData() {
        // Test all zeros
        byte[] zeros = new byte[64];
        assertEquals(computeJavaSM3(zeros), computePythonSM3(zeros), 
                    "Should match for all zeros");
        
        // Test all ones
        byte[] ones = new byte[64];
        for (int i = 0; i < ones.length; i++) {
            ones[i] = (byte) 0xFF;
        }
        assertEquals(computeJavaSM3(ones), computePythonSM3(ones), 
                    "Should match for all ones");
        
        // Test alternating pattern
        byte[] alternating = new byte[64];
        for (int i = 0; i < alternating.length; i++) {
            alternating[i] = (byte) (i % 2 == 0 ? 0xAA : 0x55);
        }
        assertEquals(computeJavaSM3(alternating), computePythonSM3(alternating), 
                    "Should match for alternating pattern");
    }
    
    @Test
    @Order(5)
    @DisplayName("Unicode strings - Chinese, Japanese, Korean")
    public void testUnicodeStrings() {
        String[] unicodeInputs = {
            "你好世界",  // Chinese
            "こんにちは", // Japanese
            "안녕하세요",  // Korean
            "مرحبا",     // Arabic
            "🎉🎊🎈"      // Emojis
        };
        
        System.out.println("\n=== SM3 Unicode Test ===");
        for (String input : unicodeInputs) {
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            String javaHash = computeJavaSM3(inputBytes);
            String pythonHash = computePythonSM3(inputBytes);
            
            System.out.println("Input: " + input);
            System.out.println("Java:   " + javaHash);
            System.out.println("Python: " + pythonHash);
            System.out.println();
            
            assertEquals(javaHash, pythonHash, 
                        "Python and Java SM3 hashes should match for Unicode: " + input);
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Block boundary tests - 64 byte blocks")
    public void testBlockBoundaries() {
        // SM3 processes data in 64-byte blocks
        int[] sizes = {0, 1, 63, 64, 65, 127, 128, 129};
        
        System.out.println("\n=== SM3 Block Boundary Test ===");
        for (int size : sizes) {
            byte[] input = new byte[size];
            for (int i = 0; i < size; i++) {
                input[i] = (byte) i;
            }
            
            String javaHash = computeJavaSM3(input);
            String pythonHash = computePythonSM3(input);
            
            System.out.println("Size " + size + " bytes: " + 
                             (javaHash.equals(pythonHash) ? "✓" : "✗"));
            
            assertEquals(javaHash, pythonHash, 
                        "Python and Java SM3 hashes should match for size " + size);
        }
    }
}
