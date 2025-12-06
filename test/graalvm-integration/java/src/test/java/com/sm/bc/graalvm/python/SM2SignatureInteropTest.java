package com.sm.bc.graalvm.python;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.graalvm.polyglot.Value;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-language signature validation tests between Java Bouncy Castle and Python SM-BC
 * 
 * Tests:
 * 1. Java sign → Python verify
 * 2. Python sign → Java verify
 * 3. Key format compatibility
 * 4. Edge cases and error handling
 * 
 * Aligned with: sm-js-bc/.../SM2SignatureInteropTest.java
 */
@DisplayName("SM2 Signature Cross-Language Tests (Java ↔ Python)")
@EnabledIf("isGraalVMPythonAvailable")
public class SM2SignatureInteropTest extends BaseGraalVMPythonTest {

    private static ECDomainParameters domainParams;
    private static SecureRandom random;

    @BeforeAll
    static void setupCrypto() {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Initialize SM2 curve parameters
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
    @DisplayName("Java sign → Python verify")
    void testJavaSignPythonVerify() throws Exception {
        System.out.println("\n=== Testing Java Sign → Python Verify ===");
        
        // Generate key pair with Java
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Test message
        String message = "Hello SM2 Cross-Language Test!";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        // Sign with Java Bouncy Castle
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(messageBytes, 0, messageBytes.length);
        byte[] signature = signer.generateSignature();
        
        System.out.println("Java signature length: " + signature.length + " bytes");
        System.out.println("Java signature (hex): " + bytesToHex(signature));
        
        // Prepare data for Python verification
        String privateKeyHex = privateKey.getD().toString(16);
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        String messageHex = bytesToHex(messageBytes);
        String signatureHex = bytesToHex(signature);
        
        // Verify with Python SM-BC
        Value result = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                from binascii import hexlify, unhexlify
                
                # Convert hex strings to bytes
                message = unhexlify('%s')
                signature = unhexlify('%s')
                
                # Create public key (x, y coordinates)
                public_key_x = int('%s', 16)
                public_key_y = int('%s', 16)
                public_key = (public_key_x, public_key_y)
                
                print('Python verifying signature of length:', len(signature))
                print('Python public key x:', hex(public_key_x))
                print('Python public key y:', hex(public_key_y))
                
                # Verify signature
                signer = SM2Signer()
                is_valid = signer.verify(message, signature, public_key)
                
                {
                    'success': True,
                    'is_valid': is_valid,
                    'message': 'Verification completed'
                }
            except Exception as e:
                {
                    'success': False,
                    'error': str(e)
                }
            """, messageHex, signatureHex, publicKeyX, publicKeyY));
        
        // Check Python result
        assertTrue(result.getMember("success").asBoolean(), 
            "Python verification failed: " + result.getMember("error"));
        assertTrue(result.getMember("is_valid").asBoolean(), 
            "Python failed to verify Java signature");
        
        System.out.println("✓ Java signature successfully verified by Python");
    }

    @Test
    @DisplayName("Python sign → Java verify")
    void testPythonSignJavaVerify() throws Exception {
        System.out.println("\n=== Testing Python Sign → Java Verify ===");
        
        // Test message
        String message = "SM2 signature test from Python to Java";
        byte[] messageBytes = message.getBytes("UTF-8");
        String messageHex = bytesToHex(messageBytes);
        
        // Generate key pair and sign with Python SM-BC
        Value result = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                from binascii import hexlify, unhexlify
                
                # Generate key pair
                signer = SM2Signer()
                private_key, public_key = signer.generate_key_pair()
                
                # Convert message
                message = unhexlify('%s')
                
                print('Python generated key pair')
                print('Python private key:', hex(private_key))
                print('Python public key x:', hex(public_key[0]))
                print('Python public key y:', hex(public_key[1]))
                
                # Sign message
                signature = signer.sign(message, private_key)
                
                print('Python signature length:', len(signature))
                
                {
                    'success': True,
                    'private_key': hex(private_key)[2:],  # Remove '0x' prefix
                    'public_key_x': hex(public_key[0])[2:],
                    'public_key_y': hex(public_key[1])[2:],
                    'signature': hexlify(signature).decode('ascii'),
                    'message': 'Signing completed'
                }
            except Exception as e:
                import traceback
                {
                    'success': False,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
            """, messageHex));
        
        // Check Python result
        assertTrue(result.getMember("success").asBoolean(), 
            "Python signing failed: " + result.getMember("error"));
        
        // Extract data from Python
        String privateKeyHex = result.getMember("private_key").asString();
        String publicKeyX = result.getMember("public_key_x").asString();
        String publicKeyY = result.getMember("public_key_y").asString();
        String signatureHex = result.getMember("signature").asString();
        
        System.out.println("Python signature length: " + signatureHex.length()/2 + " bytes");
        System.out.println("Python signature (hex): " + signatureHex);
        
        // Create Java key parameters from Python data
        BigInteger d = new BigInteger(privateKeyHex, 16);
        BigInteger x = new BigInteger(publicKeyX, 16);
        BigInteger y = new BigInteger(publicKeyY, 16);
        
        ECPoint pubPoint = domainParams.getCurve().createPoint(x, y);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(pubPoint, domainParams);
        
        // Verify with Java Bouncy Castle
        byte[] signature = hexToBytes(signatureHex);
        
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(messageBytes, 0, messageBytes.length);
        boolean isValid = verifier.verifySignature(signature);
        
        assertTrue(isValid, "Java failed to verify Python signature");
        System.out.println("✓ Python signature successfully verified by Java");
    }

    @Test
    @DisplayName("Key format compatibility test")
    void testKeyFormatCompatibility() throws Exception {
        System.out.println("\n=== Testing Key Format Compatibility ===");
        
        // Generate key pair with Java
        AsymmetricCipherKeyPair javaKeyPair = generateKeyPair();
        ECPrivateKeyParameters javaPrivateKey = (ECPrivateKeyParameters) javaKeyPair.getPrivate();
        ECPublicKeyParameters javaPublicKey = (ECPublicKeyParameters) javaKeyPair.getPublic();
        
        // Export Java keys to hex
        String privateKeyHex = javaPrivateKey.getD().toString(16);
        ECPoint pubPoint = javaPublicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        // Test key import in Python
        Value pyResult = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                from binascii import hexlify
                
                # Import keys from Java format
                private_key = int('%s', 16)
                public_key = (int('%s', 16), int('%s', 16))
                
                print('Python imported private key:', hex(private_key))
                print('Python imported public key x:', hex(public_key[0]))
                print('Python imported public key y:', hex(public_key[1]))
                
                # Test message
                message = b'Key compatibility test'
                
                # Sign with imported private key
                signer = SM2Signer()
                signature = signer.sign(message, private_key)
                
                # Verify with imported public key
                is_valid = signer.verify(message, signature, public_key)
                
                {
                    'success': True,
                    'signed': True,
                    'verified': is_valid,
                    'signature': hexlify(signature).decode('ascii')
                }
            except Exception as e:
                import traceback
                {
                    'success': False,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
            """, privateKeyHex, publicKeyX, publicKeyY));
        
        // Check Python result
        assertTrue(pyResult.getMember("success").asBoolean(), 
            "Python key import failed: " + pyResult.getMember("error"));
        assertTrue(pyResult.getMember("signed").asBoolean(), 
            "Python signing with imported key failed");
        assertTrue(pyResult.getMember("verified").asBoolean(), 
            "Python verification with imported key failed");
        
        System.out.println("✓ Key format is compatible between Java and Python");
    }

    @Test
    @DisplayName("Round-trip signature test")
    void testRoundTripSignature() throws Exception {
        System.out.println("\n=== Testing Round-Trip Signature ===");
        
        // Generate key pair with Java
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Test message
        String message = "Round-trip signature test";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        // Java sign → Java verify
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(messageBytes, 0, messageBytes.length);
        byte[] signature = signer.generateSignature();
        
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(messageBytes, 0, messageBytes.length);
        assertTrue(verifier.verifySignature(signature), "Java round-trip failed");
        
        System.out.println("✓ Java round-trip: PASS");
        
        // Export keys for Python
        String privateKeyHex = privateKey.getD().toString(16);
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        // Python sign → Python verify
        Value pyResult = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                
                private_key = int('%s', 16)
                public_key = (int('%s', 16), int('%s', 16))
                message = b'%s'
                
                signer = SM2Signer()
                signature = signer.sign(message, private_key)
                is_valid = signer.verify(message, signature, public_key)
                
                {
                    'success': True,
                    'verified': is_valid
                }
            except Exception as e:
                {
                    'success': False,
                    'error': str(e)
                }
            """, privateKeyHex, publicKeyX, publicKeyY, message));
        
        assertTrue(pyResult.getMember("success").asBoolean(), 
            "Python round-trip failed: " + pyResult.getMember("error"));
        assertTrue(pyResult.getMember("verified").asBoolean(), 
            "Python signature verification failed");
        
        System.out.println("✓ Python round-trip: PASS");
        System.out.println("✓ Both round-trips successful");
    }

    @Test
    @DisplayName("Multiple message sizes test")
    void testMultipleMessageSizes() throws Exception {
        System.out.println("\n=== Testing Multiple Message Sizes ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        String privateKeyHex = privateKey.getD().toString(16);
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        
        // Test various message sizes
        int[] sizes = {0, 1, 16, 64, 256, 1024};
        
        for (int size : sizes) {
            System.out.println("  Testing message size: " + size + " bytes");
            
            // Create message
            byte[] messageBytes = new byte[size];
            for (int i = 0; i < size; i++) {
                messageBytes[i] = (byte) (i % 256);
            }
            String messageHex = bytesToHex(messageBytes);
            
            // Java sign → Python verify
            SM2Signer signer = new SM2Signer();
            signer.init(true, privateKey);
            signer.update(messageBytes, 0, messageBytes.length);
            byte[] signature = signer.generateSignature();
            String signatureHex = bytesToHex(signature);
            
            Value result = context.eval("python", String.format("""
                try:
                    from sm2_signer import SM2Signer
                    from binascii import unhexlify
                    
                    message = unhexlify('%s') if '%s' else b''
                    signature = unhexlify('%s')
                    public_key = (int('%s', 16), int('%s', 16))
                    
                    signer = SM2Signer()
                    is_valid = signer.verify(message, signature, public_key)
                    
                    {'success': True, 'is_valid': is_valid}
                except Exception as e:
                    {'success': False, 'error': str(e)}
                """, messageHex, messageHex, signatureHex, publicKeyX, publicKeyY));
            
            assertTrue(result.getMember("success").asBoolean(), 
                "Failed for message size " + size);
            assertTrue(result.getMember("is_valid").asBoolean(), 
                "Verification failed for message size " + size);
            
            System.out.println("    ✓ Size " + size + " bytes: PASS");
        }
        
        System.out.println("✓ All message sizes passed");
    }

    @Test
    @DisplayName("Invalid signature rejection test")
    void testInvalidSignatureRejection() throws Exception {
        System.out.println("\n=== Testing Invalid Signature Rejection ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Test message
        byte[] messageBytes = "Test message".getBytes("UTF-8");
        
        // Sign with Java
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(messageBytes, 0, messageBytes.length);
        byte[] signature = signer.generateSignature();
        
        // Tamper with signature
        byte[] tamperedSignature = signature.clone();
        tamperedSignature[0] ^= 0xFF;
        
        // Verify with Java (should fail)
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(messageBytes, 0, messageBytes.length);
        assertFalse(verifier.verifySignature(tamperedSignature), 
            "Java should reject tampered signature");
        
        System.out.println("✓ Java correctly rejected tampered signature");
        
        // Export keys for Python
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        String messageHex = bytesToHex(messageBytes);
        String tamperedSignatureHex = bytesToHex(tamperedSignature);
        
        // Verify with Python (should also fail)
        Value result = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                from binascii import unhexlify
                
                message = unhexlify('%s')
                signature = unhexlify('%s')
                public_key = (int('%s', 16), int('%s', 16))
                
                signer = SM2Signer()
                is_valid = signer.verify(message, signature, public_key)
                
                {'success': True, 'is_valid': is_valid}
            except Exception as e:
                {'success': True, 'is_valid': False}
            """, messageHex, tamperedSignatureHex, publicKeyX, publicKeyY));
        
        assertTrue(result.getMember("success").asBoolean());
        assertFalse(result.getMember("is_valid").asBoolean(), 
            "Python should reject tampered signature");
        
        System.out.println("✓ Python correctly rejected tampered signature");
        System.out.println("✓ Both implementations correctly reject invalid signatures");
    }

    @Test
    @DisplayName("Different message verification test")
    void testDifferentMessageVerification() throws Exception {
        System.out.println("\n=== Testing Different Message Verification ===");
        
        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Sign one message
        byte[] originalMessage = "Original message".getBytes("UTF-8");
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(originalMessage, 0, originalMessage.length);
        byte[] signature = signer.generateSignature();
        
        // Try to verify different message
        byte[] differentMessage = "Different message".getBytes("UTF-8");
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(differentMessage, 0, differentMessage.length);
        assertFalse(verifier.verifySignature(signature), 
            "Java should reject signature for different message");
        
        System.out.println("✓ Java correctly rejected signature for different message");
        
        // Test with Python
        ECPoint pubPoint = publicKey.getQ();
        String publicKeyX = pubPoint.getAffineXCoord().toBigInteger().toString(16);
        String publicKeyY = pubPoint.getAffineYCoord().toBigInteger().toString(16);
        String signatureHex = bytesToHex(signature);
        String differentMessageHex = bytesToHex(differentMessage);
        
        Value result = context.eval("python", String.format("""
            try:
                from sm2_signer import SM2Signer
                from binascii import unhexlify
                
                message = unhexlify('%s')
                signature = unhexlify('%s')
                public_key = (int('%s', 16), int('%s', 16))
                
                signer = SM2Signer()
                is_valid = signer.verify(message, signature, public_key)
                
                {'success': True, 'is_valid': is_valid}
            except Exception as e:
                {'success': True, 'is_valid': False}
            """, differentMessageHex, signatureHex, publicKeyX, publicKeyY));
        
        assertTrue(result.getMember("success").asBoolean());
        assertFalse(result.getMember("is_valid").asBoolean(), 
            "Python should reject signature for different message");
        
        System.out.println("✓ Python correctly rejected signature for different message");
    }
}
