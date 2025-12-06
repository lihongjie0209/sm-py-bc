package com.sm.bc.graalvm;

import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-language SM2 signature interoperability tests
 * Validates Python ↔ Java signature compatibility
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SM2SignatureInteropTest extends BaseGraalVMTest {
    
    // Test key pair (from standard test vectors)
    private static final String PRIVATE_KEY = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
    private static final String PUBLIC_KEY = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
    
    @BeforeEach
    @Override
    public void setupGraalVM() {
        Assumptions.assumeTrue(isGraalVMPythonAvailable(),
                "GraalVM Python support not available - skipping test");
        super.setupGraalVM();
    }
    
    @Test
    @Order(1)
    @DisplayName("Java sign → Python verify")
    public void testJavaSignPythonVerify() throws Exception {
        byte[] message = "Hello, SM2!".getBytes(StandardCharsets.UTF_8);
        
        // Java signs
        String signature = signWithJavaSM2(message, PRIVATE_KEY);
        
        System.out.println("\n=== Testing Java Sign → Python Verify ===");
        System.out.println("Message: Hello, SM2!");
        System.out.println("Java signature length: " + signature.length() / 2 + " bytes");
        System.out.println("Java signature: " + signature.substring(0, Math.min(64, signature.length())) + "...");
        
        // Python verifies
        boolean verified = verifyWithPythonSM2(message, signature, PUBLIC_KEY);
        
        assertTrue(verified, "Python should successfully verify Java signature");
        System.out.println("✓ Java signature successfully verified by Python");
    }
    
    @Test
    @Order(2)
    @DisplayName("Python sign → Java verify")
    public void testPythonSignJavaVerify() throws Exception {
        byte[] message = "Hello, SM2!".getBytes(StandardCharsets.UTF_8);
        
        // Python signs
        String signature = signWithPythonSM2(message, PRIVATE_KEY);
        
        System.out.println("\n=== Testing Python Sign → Java Verify ===");
        System.out.println("Message: Hello, SM2!");
        System.out.println("Python signature length: " + signature.length() / 2 + " bytes");
        System.out.println("Python signature: " + signature.substring(0, Math.min(64, signature.length())) + "...");
        
        // Java verifies
        boolean verified = verifyWithJavaSM2(message, signature, PUBLIC_KEY);
        
        assertTrue(verified, "Java should successfully verify Python signature");
        System.out.println("✓ Python signature successfully verified by Java");
    }
    
    @Test
    @Order(3)
    @DisplayName("Bidirectional signature verification")
    public void testBidirectionalVerification() throws Exception {
        byte[] message = "Test message for cross-verification".getBytes(StandardCharsets.UTF_8);
        
        System.out.println("\n=== Bidirectional Signature Verification ===");
        
        // Java sign
        String javaSignature = signWithJavaSM2(message, PRIVATE_KEY);
        System.out.println("Java signature: " + javaSignature.substring(0, 32) + "...");
        
        // Python sign
        String pythonSignature = signWithPythonSM2(message, PRIVATE_KEY);
        System.out.println("Python signature: " + pythonSignature.substring(0, 32) + "...");
        
        // Cross verify
        boolean pythonVerifiesJava = verifyWithPythonSM2(message, javaSignature, PUBLIC_KEY);
        boolean javaVerifiesPython = verifyWithJavaSM2(message, pythonSignature, PUBLIC_KEY);
        
        assertTrue(pythonVerifiesJava, "Python should verify Java signature");
        assertTrue(javaVerifiesPython, "Java should verify Python signature");
        
        System.out.println("✓ Both implementations can verify each other's signatures");
    }
    
    @Test
    @Order(4)
    @DisplayName("Various message sizes")
    public void testVariousMessageSizes() throws Exception {
        int[] sizes = {0, 1, 16, 64, 256, 1024};
        
        System.out.println("\n=== Testing Various Message Sizes ===");
        
        for (int size : sizes) {
            byte[] message = new byte[size];
            for (int i = 0; i < size; i++) {
                message[i] = (byte) (i % 256);
            }
            
            String javaSignature = signWithJavaSM2(message, PRIVATE_KEY);
            String pythonSignature = signWithPythonSM2(message, PRIVATE_KEY);
            
            boolean pythonVerifiesJava = verifyWithPythonSM2(message, javaSignature, PUBLIC_KEY);
            boolean javaVerifiesPython = verifyWithJavaSM2(message, pythonSignature, PUBLIC_KEY);
            
            System.out.println("Size " + size + " bytes: " + 
                             (pythonVerifiesJava && javaVerifiesPython ? "✓" : "✗"));
            
            assertTrue(pythonVerifiesJava, "Python should verify Java signature for size " + size);
            assertTrue(javaVerifiesPython, "Java should verify Python signature for size " + size);
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Invalid signature detection")
    public void testInvalidSignature() throws Exception {
        byte[] message = "Test message".getBytes(StandardCharsets.UTF_8);
        
        String validSignature = signWithJavaSM2(message, PRIVATE_KEY);
        
        // Corrupt the signature
        String corruptedSignature = "FF" + validSignature.substring(2);
        
        System.out.println("\n=== Testing Invalid Signature Detection ===");
        System.out.println("Original signature: " + validSignature.substring(0, 32) + "...");
        System.out.println("Corrupted signature: " + corruptedSignature.substring(0, 32) + "...");
        
        // Both implementations should reject corrupted signature
        boolean pythonAccepts = false;
        boolean javaAccepts = false;
        
        try {
            pythonAccepts = verifyWithPythonSM2(message, corruptedSignature, PUBLIC_KEY);
        } catch (Exception e) {
            System.out.println("Python correctly rejected: " + e.getMessage());
        }
        
        try {
            javaAccepts = verifyWithJavaSM2(message, corruptedSignature, PUBLIC_KEY);
        } catch (Exception e) {
            System.out.println("Java correctly rejected: " + e.getMessage());
        }
        
        assertFalse(pythonAccepts, "Python should reject corrupted signature");
        assertFalse(javaAccepts, "Java should reject corrupted signature");
        
        System.out.println("✓ Both implementations correctly reject invalid signatures");
    }
    
    @Test
    @Order(6)
    @DisplayName("Unicode message signing")
    public void testUnicodeMessages() throws Exception {
        String[] messages = {
            "你好，国密SM2！",
            "こんにちは、SM2！",
            "안녕하세요, SM2!",
            "🔐 Secure with SM2 🔒"
        };
        
        System.out.println("\n=== Testing Unicode Messages ===");
        
        for (String msg : messages) {
            byte[] messageBytes = msg.getBytes(StandardCharsets.UTF_8);
            
            String javaSignature = signWithJavaSM2(messageBytes, PRIVATE_KEY);
            String pythonSignature = signWithPythonSM2(messageBytes, PRIVATE_KEY);
            
            boolean pythonVerifiesJava = verifyWithPythonSM2(messageBytes, javaSignature, PUBLIC_KEY);
            boolean javaVerifiesPython = verifyWithJavaSM2(messageBytes, pythonSignature, PUBLIC_KEY);
            
            System.out.println("Message: " + msg.substring(0, Math.min(20, msg.length())) + 
                             " - " + (pythonVerifiesJava && javaVerifiesPython ? "✓" : "✗"));
            
            assertTrue(pythonVerifiesJava, "Python should verify Java signature for: " + msg);
            assertTrue(javaVerifiesPython, "Java should verify Python signature for: " + msg);
        }
        
        System.out.println("✓ All Unicode messages signed and verified successfully");
    }
}
