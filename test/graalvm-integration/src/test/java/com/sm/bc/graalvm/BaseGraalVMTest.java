package com.sm.bc.graalvm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.security.SecureRandom;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Base class for GraalVM Polyglot tests that interact with Python SM-BC library
 */
public abstract class BaseGraalVMTest {
    
    protected Context pythonContext;
    
    // Path to the SM-BC Python library
    protected static final String SM_BC_PYTHON_PATH = "../../src";
    
    /**
     * Check if GraalVM Python support is available
     */
    protected static boolean isGraalVMPythonAvailable() {
        try {
            Context testContext = Context.newBuilder("python")
                    .allowAllAccess(true)
                    .allowExperimentalOptions(true)
                    .option("python.ForceImportSite", "false")
                    .build();
            testContext.close();
            return true;
        } catch (Exception e) {
            System.err.println("GraalVM Python not available: " + e.getMessage());
            return false;
        }
    }
    
    @BeforeEach
    public void setupGraalVM() {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Create GraalVM context with Python support
        pythonContext = Context.newBuilder("python")
                .allowAllAccess(true)
                .allowExperimentalOptions(true)
                .option("python.ForceImportSite", "false")
                .option("python.PythonPath", SM_BC_PYTHON_PATH)
                .build();
        
        // Import the SM-BC library
        loadSmBcLibrary();
    }
    
    @AfterEach
    public void cleanupGraalVM() {
        if (pythonContext != null) {
            pythonContext.close();
        }
    }
    
    /**
     * Load the SM-BC Python library
     */
    private void loadSmBcLibrary() {
        try {
            pythonContext.eval("python", "import sys");
            pythonContext.eval("python", "sys.path.insert(0, '" + SM_BC_PYTHON_PATH + "')");
            
            pythonContext.eval("python", "from sm_bc.sm2_signer import SM2Signer");
            pythonContext.eval("python", "from sm_bc.sm3_digest import SM3Digest");
            pythonContext.eval("python", "from sm_bc.sm2 import SM2");
            
            System.out.println("Successfully loaded SM-BC Python library");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load SM-BC Python library: " + e.getMessage(), e);
        }
    }
    
    /**
     * Execute Python code
     */
    protected Value evalPython(String code) {
        return pythonContext.eval("python", code);
    }
    
    /**
     * Convert byte array to Python bytes
     */
    protected Value bytesToPythonBytes(byte[] bytes) {
        StringBuilder hexStr = new StringBuilder();
        for (byte b : bytes) {
            hexStr.append(String.format("%02x", b));
        }
        return evalPython("bytes.fromhex('" + hexStr.toString() + "')");
    }
    
    /**
     * Convert Python bytes to byte array
     */
    protected byte[] pythonBytesToBytes(Value pythonBytes) {
        String hex = evalPython("lambda b: b.hex()").execute(pythonBytes).asString();
        return hexToBytes(hex);
    }
    
    /**
     * Convert hex string to byte array
     */
    protected static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Convert byte array to hex string
     */
    protected static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    /**
     * Compute SM3 hash using Java Bouncy Castle
     */
    protected String computeJavaSM3(byte[] input) {
        SM3Digest digest = new SM3Digest();
        digest.update(input, 0, input.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return bytesToHex(result);
    }
    
    /**
     * Compute SM3 hash using Python implementation
     */
    protected String computePythonSM3(byte[] input) {
        String hexInput = bytesToHex(input);
        Value result = evalPython(String.format("""
            def compute_sm3():
                data = bytes.fromhex('%s')
                digest = SM3Digest()
                digest.update_array(data, 0, len(data))
                result = bytearray(digest.get_digest_size())
                digest.do_final(result, 0)
                return result.hex()
            compute_sm3()
        """, hexInput));
        return result.asString();
    }
    
    /**
     * Sign message using Java Bouncy Castle SM2
     */
    protected String signWithJavaSM2(byte[] message, String privateKeyHex) throws Exception {
        X9ECParameters sm2Params = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2Params.getCurve(),
                sm2Params.getG(),
                sm2Params.getN(),
                sm2Params.getH()
        );
        
        BigInteger d = new BigInteger(privateKeyHex, 16);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParams);
        
        SM2Signer signer = new SM2Signer();
        ParametersWithRandom paramsWithRandom = new ParametersWithRandom(privateKey, new SecureRandom());
        signer.init(true, paramsWithRandom);
        signer.update(message, 0, message.length);
        
        byte[] signature = signer.generateSignature();
        return bytesToHex(signature);
    }
    
    /**
     * Verify signature using Java Bouncy Castle SM2
     */
    protected boolean verifyWithJavaSM2(byte[] message, String signatureHex, String publicKeyHex) throws Exception {
        X9ECParameters sm2Params = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2Params.getCurve(),
                sm2Params.getG(),
                sm2Params.getN(),
                sm2Params.getH()
        );
        
        if (!publicKeyHex.startsWith("04")) {
            throw new IllegalArgumentException("Public key must be in uncompressed format (04 + x + y)");
        }
        
        int coordLen = (publicKeyHex.length() - 2) / 2;
        String xHex = publicKeyHex.substring(2, 2 + coordLen);
        String yHex = publicKeyHex.substring(2 + coordLen);
        
        BigInteger x = new BigInteger(xHex, 16);
        BigInteger y = new BigInteger(yHex, 16);
        
        ECPoint q = domainParams.getCurve().createPoint(x, y);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(q, domainParams);
        
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        
        byte[] signature = hexToBytes(signatureHex);
        return verifier.verifySignature(signature);
    }
    
    /**
     * Sign message using Python SM2
     */
    protected String signWithPythonSM2(byte[] message, String privateKeyHex) {
        String messageHex = bytesToHex(message);
        Value result = evalPython(String.format("""
            def sign_message():
                message = bytes.fromhex('%s')
                private_key_int = int('%s', 16)
                
                from sm_bc.ec_private_key_parameters import ECPrivateKeyParameters
                from sm_bc.parameters_with_random import ParametersWithRandom
                from sm_bc.secure_random import SecureRandom
                
                domain_params = SM2.get_parameters()
                private_key = ECPrivateKeyParameters(private_key_int, domain_params)
                
                signer = SM2Signer()
                random = SecureRandom()
                signer.init(True, ParametersWithRandom(private_key, random))
                signer.update(message, 0, len(message))
                
                signature = signer.generate_signature()
                return signature.hex()
            sign_message()
        """, messageHex, privateKeyHex));
        return result.asString();
    }
    
    /**
     * Verify signature using Python SM2
     */
    protected boolean verifyWithPythonSM2(byte[] message, String signatureHex, String publicKeyHex) {
        String messageHex = bytesToHex(message);
        Value result = evalPython(String.format("""
            def verify_signature():
                message = bytes.fromhex('%s')
                signature = bytes.fromhex('%s')
                public_key_hex = '%s'
                
                from sm_bc.ec_public_key_parameters import ECPublicKeyParameters
                
                if not public_key_hex.startswith('04'):
                    raise ValueError('Public key must be in uncompressed format')
                
                coord_len = (len(public_key_hex) - 2) // 2
                x_hex = public_key_hex[2:2+coord_len]
                y_hex = public_key_hex[2+coord_len:]
                
                x = int(x_hex, 16)
                y = int(y_hex, 16)
                
                domain_params = SM2.get_parameters()
                curve = domain_params.get_curve()
                q = curve.create_point(x, y)
                public_key = ECPublicKeyParameters(q, domain_params)
                
                verifier = SM2Signer()
                verifier.init(False, public_key)
                verifier.update(message, 0, len(message))
                
                return verifier.verify_signature(signature)
            verify_signature()
        """, messageHex, signatureHex, publicKeyHex));
        return result.asBoolean();
    }
}
