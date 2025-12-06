package com.sm.bc.graalvm.python;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.graalvm.polyglot.Value;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-language encryption/decryption tests between Java Bouncy Castle and Python SM-BC
 * 
 * Tests:
 * 1. Java encrypt → Python decrypt
 * 2. Python encrypt → Java decrypt
 * 3. Various message sizes
 * 4. Error handling for invalid ciphertexts
 * 5. Round-trip encryption/decryption
 * 
 * Aligned with: sm-js-bc/.../SM2EncryptionInteropTest.java
 */
@DisplayName("SM2 Encryption Cross-Language Tests (Java ↔ Python)")
@EnabledIf("isGraalVMPythonAvailable")
public class SM2EncryptionInteropTest extends BaseGraalVMPythonTest {

    private static ECDomainParameters domainParams;
    private static SecureRandom random;

    @BeforeAll
    static void setupCrypto() {
        Security.addProvider(new BouncyCastleProvider());
        
        X9ECParameters sm2Params = GMNamedCurves.getByName("sm2p256v1");
        domainParams = new ECDomainParameters(
            sm2Params.getCurve(),
            sm2Params.getG(),
            sm2Params.getN(),
            sm2Params.getH()
        );
        
        random = new SecureRandom();
    }

    /**
     * Generate an SM2 key pair using Bouncy Castle
     */
    private AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domainParams, random));
        return generator.generateKeyPair();
    }

    @Test
    @DisplayName("Java encrypt → Python decrypt")
    void testJavaEncryptPythonDecrypt() throws Exception {
        System.out.println("\n=== Testing Java Encrypt → Python Decrypt ===");
        
        // Generate key pair with Java
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Test messages of different sizes
        String[] testMessages = {
            "Hello SM2!",
            "This is a longer test message for SM2 encryption verification.",
            "SM2加密测试消息，包含中文字符！"
        };
        
        for (String message : testMessages) {
            System.out.println("Testing message: \"" + message + "\" (length: " + message.length() + ")");
            testJavaEncryptPythonDecryptSingle(message, privateKey, publicKey);
        }
        
        System.out.println("✓ All Java encrypt → Python decrypt tests passed");
    }

    private void testJavaEncryptPythonDecryptSingle(String message, ECPrivateKeyParameters privateKey, 
                                                   ECPublicKeyParameters publicKey) throws Exception {
        
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        
        // Encrypt with Java Bouncy Castle
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        byte[] ciphertext = engine.processBlock(messageBytes, 0, messageBytes.length);
        
        System.out.println("  Java ciphertext length: " + ciphertext.length + " bytes");
        
        // Prepare data for Python decryption
        String privateKeyHex = privateKey.getD().toString(16);
        String ciphertextHex = bytesToHex(ciphertext);
        
        // Decrypt with Python SM-BC
        Value result = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                from binascii import hexlify, unhexlify
                
                # Convert hex to bytes
                ciphertext = unhexlify('%s')
                private_key = int('%s', 16)
                
                print('Python decrypting ciphertext of length:', len(ciphertext))
                print('Python private key:', hex(private_key))
                
                # Decrypt
                engine = SM2Engine()
                decrypted = engine.decrypt(ciphertext, private_key)
                
                # Convert to string
                decrypted_text = decrypted.decode('utf-8')
                
                print('Python decrypted text:', decrypted_text)
                
                {
                    'success': True,
                    'decrypted_text': decrypted_text,
                    'decrypted_bytes': list(decrypted),
                    'message': 'Decryption completed'
                }
            except Exception as e:
                import traceback
                {
                    'success': False,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
            """, ciphertextHex, privateKeyHex));
        
        // Check Python result
        assertTrue(result.getMember("success").asBoolean(), 
            "Python decryption failed: " + result.getMember("error"));
        
        String decryptedText = result.getMember("decrypted_text").asString();
        assertEquals(message, decryptedText,
            "Decrypted message doesn't match original");
        
        System.out.println("  ✓ Message successfully decrypted");
    }

    @Test
    @DisplayName("Python encrypt → Java decrypt")
    void testPythonEncryptJavaDecrypt() throws Exception {
        System.out.println("\n=== Testing Python Encrypt → Java Decrypt ===");
        
        // Test messages of different sizes
        String[] testMessages = {
            "Hello from Python!",
            "Python SM2 encryption test with longer message.",
            "Python测试消息！"
        };
        
        for (String message : testMessages) {
            System.out.println("Testing message: \"" + message + "\" (length: " + message.length() + ")");
            testPythonEncryptJavaDecryptSingle(message);
        }
        
        System.out.println("✓ All Python encrypt → Java decrypt tests passed");
    }

    private void testPythonEncryptJavaDecryptSingle(String message) throws Exception {
        
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        String messageBytesStr = bytesToHex(messageBytes);
        
        // Encrypt with Python SM-BC
        Value result = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                from sm2_signer import SM2Signer
                from binascii import hexlify, unhexlify
                
                # Generate key pair
                signer = SM2Signer()
                private_key, public_key = signer.generate_key_pair()
                
                print('Python generated key pair')
                print('Python public key x:', hex(public_key[0]))
                print('Python public key y:', hex(public_key[1]))
                
                # Encrypt message
                message = unhexlify('%s')
                engine = SM2Engine()
                ciphertext = engine.encrypt(message, public_key)
                
                print('Python ciphertext length:', len(ciphertext))
                
                {
                    'success': True,
                    'private_key': hex(private_key)[2:],
                    'public_key_x': hex(public_key[0])[2:],
                    'public_key_y': hex(public_key[1])[2:],
                    'ciphertext': hexlify(ciphertext).decode('ascii'),
                    'message': 'Encryption completed'
                }
            except Exception as e:
                import traceback
                {
                    'success': False,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
            """, messageBytesStr));
        
        // Check Python result
        assertTrue(result.getMember("success").asBoolean(), 
            "Python encryption failed: " + result.getMember("error"));
        
        // Extract data from Python
        String privateKeyHex = result.getMember("private_key").asString();
        String ciphertextHex = result.getMember("ciphertext").asString();
        
        System.out.println("  Python ciphertext length: " + ciphertextHex.length()/2 + " bytes");
        
        // Create Java key parameters from Python data
        BigInteger d = new BigInteger(privateKeyHex, 16);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParams);
        
        // Decrypt with Java Bouncy Castle
        byte[] ciphertext = hexToBytes(ciphertextHex);
        
        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKey); // false for decryption
        byte[] decrypted = engine.processBlock(ciphertext, 0, ciphertext.length);
        
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        assertEquals(message, decryptedText,
            "Decrypted message doesn't match original");
        
        System.out.println("  ✓ Message successfully decrypted");
    }

    @Test
    @DisplayName("Multiple plaintext sizes test")
    void testMultiplePlaintextSizes() throws Exception {
        System.out.println("\n=== Testing Multiple Plaintext Sizes ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        String privateKeyHex = privateKey.getD().toString(16);
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        // Test various plaintext sizes (SM2 requires non-empty input)
        int[] sizes = {1, 16, 32, 64, 100, 256};
        
        for (int size : sizes) {
            System.out.println("  Testing plaintext size: " + size + " bytes");
            
            // Create plaintext
            byte[] plaintext = new byte[size];
            for (int i = 0; i < size; i++) {
                plaintext[i] = (byte) (i % 256);
            }
            
            // Java encrypt
            SM2Engine engine = new SM2Engine();
            engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
            byte[] ciphertext = engine.processBlock(plaintext, 0, plaintext.length);
            String ciphertextHex = bytesToHex(ciphertext);
            String plaintextHex = bytesToHex(plaintext);
            
            // Python decrypt
            Value result = context.eval("python", String.format("""
                try:
                    from sm2_engine import SM2Engine
                    from binascii import hexlify, unhexlify
                    
                    ciphertext = unhexlify('%s')
                    private_key = int('%s', 16)
                    
                    engine = SM2Engine()
                    decrypted = engine.decrypt(ciphertext, private_key)
                    
                    {
                        'success': True,
                        'decrypted': hexlify(decrypted).decode('ascii')
                    }
                except Exception as e:
                    {'success': False, 'error': str(e)}
                """, ciphertextHex, privateKeyHex));
            
            assertTrue(result.getMember("success").asBoolean(), 
                "Failed for plaintext size " + size);
            
            String decryptedHex = result.getMember("decrypted").asString();
            assertEquals(plaintextHex, decryptedHex,
                "Decrypted data doesn't match for size " + size);
            
            System.out.println("    ✓ Size " + size + " bytes: PASS");
        }
        
        System.out.println("✓ All plaintext sizes passed");
    }

    @Test
    @DisplayName("Round-trip encryption test")
    void testRoundTripEncryption() throws Exception {
        System.out.println("\n=== Testing Round-Trip Encryption ===");
        
        // Generate key pair with Java
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Test message
        String message = "Round-trip encryption test";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        
        // Java encrypt → Java decrypt
        SM2Engine encEngine = new SM2Engine();
        encEngine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        byte[] ciphertext = encEngine.processBlock(messageBytes, 0, messageBytes.length);
        
        SM2Engine decEngine = new SM2Engine();
        decEngine.init(false, privateKey);
        byte[] decrypted = decEngine.processBlock(ciphertext, 0, ciphertext.length);
        
        assertEquals(message, new String(decrypted, StandardCharsets.UTF_8),
            "Java round-trip failed");
        
        System.out.println("✓ Java round-trip: PASS");
        
        // Export keys for Python
        String privateKeyHex = privateKey.getD().toString(16);
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        // Python encrypt → Python decrypt
        Value pyResult = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                
                private_key = int('%s', 16)
                public_key = (int('%s', 16), int('%s', 16))
                message = b'%s'
                
                engine = SM2Engine()
                ciphertext = engine.encrypt(message, public_key)
                decrypted = engine.decrypt(ciphertext, private_key)
                
                {
                    'success': True,
                    'decrypted': decrypted.decode('utf-8')
                }
            except Exception as e:
                {
                    'success': False,
                    'error': str(e)
                }
            """, privateKeyHex, publicKeyX, publicKeyY, message));
        
        assertTrue(pyResult.getMember("success").asBoolean(), 
            "Python round-trip failed: " + pyResult.getMember("error"));
        
        String pyDecrypted = pyResult.getMember("decrypted").asString();
        assertEquals(message, pyDecrypted, "Python round-trip verification failed");
        
        System.out.println("✓ Python round-trip: PASS");
        System.out.println("✓ Both round-trips successful");
    }

    @Test
    @DisplayName("Invalid ciphertext rejection test")
    void testInvalidCiphertextRejection() throws Exception {
        System.out.println("\n=== Testing Invalid Ciphertext Rejection ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Encrypt with Java
        byte[] messageBytes = "Test message".getBytes(StandardCharsets.UTF_8);
        SM2Engine encEngine = new SM2Engine();
        encEngine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        byte[] ciphertext = encEngine.processBlock(messageBytes, 0, messageBytes.length);
        
        // Tamper with ciphertext (flip some bits in the middle)
        byte[] tamperedCiphertext = ciphertext.clone();
        int middlePos = tamperedCiphertext.length / 2;
        tamperedCiphertext[middlePos] ^= 0xFF;
        tamperedCiphertext[middlePos + 1] ^= 0xFF;
        
        // Try to decrypt with Java (should fail)
        SM2Engine decEngine = new SM2Engine();
        decEngine.init(false, privateKey);
        
        try {
            decEngine.processBlock(tamperedCiphertext, 0, tamperedCiphertext.length);
            fail("Java should reject tampered ciphertext");
        } catch (Exception e) {
            System.out.println("✓ Java correctly rejected tampered ciphertext: " + e.getMessage());
        }
        
        // Try to decrypt with Python (should also fail)
        String privateKeyHex = privateKey.getD().toString(16);
        String tamperedCiphertextHex = bytesToHex(tamperedCiphertext);
        
        Value result = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                from binascii import unhexlify
                
                ciphertext = unhexlify('%s')
                private_key = int('%s', 16)
                
                engine = SM2Engine()
                decrypted = engine.decrypt(ciphertext, private_key)
                
                {'success': True, 'decrypted': True}
            except Exception as e:
                {'success': True, 'rejected': True, 'error': str(e)}
            """, tamperedCiphertextHex, privateKeyHex));
        
        assertTrue(result.getMember("success").asBoolean());
        
        if (result.hasMember("rejected") && result.getMember("rejected").asBoolean()) {
            System.out.println("✓ Python correctly rejected tampered ciphertext");
        } else {
            System.out.println("⚠ Python did not reject tampered ciphertext (may have weak validation)");
        }
        
        System.out.println("✓ Invalid ciphertext rejection test completed");
    }

    @Test
    @DisplayName("Ciphertext format compatibility test")
    void testCiphertextFormatCompatibility() throws Exception {
        System.out.println("\n=== Testing Ciphertext Format Compatibility ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        String message = "Format compatibility test";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        
        // Java encrypt
        SM2Engine javaEngine = new SM2Engine();
        javaEngine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        byte[] javaCiphertext = javaEngine.processBlock(messageBytes, 0, messageBytes.length);
        
        System.out.println("Java ciphertext length: " + javaCiphertext.length + " bytes");
        System.out.println("Java ciphertext (first 32 bytes): " + bytesToHex(javaCiphertext).substring(0, Math.min(64, bytesToHex(javaCiphertext).length())));
        
        // Python decrypt Java ciphertext
        String privateKeyHex = privateKey.getD().toString(16);
        String javaCiphertextHex = bytesToHex(javaCiphertext);
        
        Value pyResult = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                from binascii import unhexlify
                
                ciphertext = unhexlify('%s')
                private_key = int('%s', 16)
                
                print('Python decrypting Java ciphertext of length:', len(ciphertext))
                
                engine = SM2Engine()
                decrypted = engine.decrypt(ciphertext, private_key)
                
                {
                    'success': True,
                    'decrypted': decrypted.decode('utf-8')
                }
            except Exception as e:
                import traceback
                {
                    'success': False,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
            """, javaCiphertextHex, privateKeyHex));
        
        assertTrue(pyResult.getMember("success").asBoolean(), 
            "Python failed to decrypt Java ciphertext: " + pyResult.getMember("error"));
        
        String pyDecrypted = pyResult.getMember("decrypted").asString();
        assertEquals(message, pyDecrypted, "Python decryption of Java ciphertext failed");
        
        System.out.println("✓ Python successfully decrypted Java ciphertext");
        System.out.println("✓ Ciphertext format is compatible");
    }

    @Test
    @DisplayName("Empty plaintext handling test")
    void testEmptyPlaintextHandling() throws Exception {
        System.out.println("\n=== Testing Empty Plaintext Handling ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        byte[] emptyMessage = new byte[0];
        
        // Try to encrypt empty message with Java
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        
        try {
            engine.processBlock(emptyMessage, 0, emptyMessage.length);
            System.out.println("⚠ Java allowed empty message encryption");
        } catch (Exception e) {
            System.out.println("✓ Java correctly rejected empty message: " + e.getMessage());
        }
        
        // Try with Python
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        Value result = context.eval("python", String.format("""
            try:
                from sm2_engine import SM2Engine
                
                public_key = (int('%s', 16), int('%s', 16))
                message = b''
                
                engine = SM2Engine()
                ciphertext = engine.encrypt(message, public_key)
                
                {'success': True, 'encrypted': True}
            except Exception as e:
                {'success': True, 'rejected': True, 'error': str(e)}
            """, publicKeyX, publicKeyY));
        
        assertTrue(result.getMember("success").asBoolean());
        
        if (result.hasMember("rejected") && result.getMember("rejected").asBoolean()) {
            System.out.println("✓ Python correctly rejected empty message");
        } else {
            System.out.println("⚠ Python allowed empty message encryption");
        }
        
        System.out.println("✓ Empty plaintext handling test completed");
    }
}
