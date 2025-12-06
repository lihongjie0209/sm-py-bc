package com.sm.bc.graalvm.python;

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
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Base class for GraalVM Python interoperability tests.
 * Provides common setup for executing Python code from Java tests.
 */
public abstract class BaseGraalVMPythonTest {
    
    protected Context context;
    protected Value pythonBindings;
    
    // Path to Python SM-BC library
    protected static final Path PYTHON_LIB_PATH = Paths.get("../../..").toAbsolutePath().normalize();
    
    static {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @BeforeEach
    public void setUp(TestInfo testInfo) throws IOException {
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("Starting test: " + testInfo.getDisplayName());
        System.out.println("═══════════════════════════════════════════════════════════════");
        
        // Create GraalVM context with Python support
        context = Context.newBuilder("python")
                .allowAllAccess(true)
                .allowIO(true)
                .option("python.ForceImportSite", "false")
                .option("python.PosixModuleBackend", "java")
                .build();
        
        pythonBindings = context.getBindings("python");
        
        // Add Python library path to sys.path
        String setupCode = String.format(
            "import sys\n" +
            "sys.path.insert(0, r'%s')\n" +
            "sys.path.insert(0, r'%s')\n",
            PYTHON_LIB_PATH.toString(),
            PYTHON_LIB_PATH.resolve("src").toString()
        );
        
        context.eval("python", setupCode);
        
        System.out.println("GraalVM Python context initialized");
        System.out.println("Python library path: " + PYTHON_LIB_PATH);
    }
    
    @AfterEach
    public void tearDown(TestInfo testInfo) {
        if (context != null) {
            context.close();
        }
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("Completed test: " + testInfo.getDisplayName());
        System.out.println("═══════════════════════════════════════════════════════════════\n");
    }
    
    /**
     * Execute Python code and return the result
     */
    protected Value evalPython(String code) {
        return context.eval("python", code);
    }
    
    /**
     * Execute Python file and return the result
     */
    protected Value evalPythonFile(Path filePath) throws IOException {
        Source source = Source.newBuilder("python", filePath.toFile()).build();
        return context.eval(source);
    }
    
    /**
     * Import a Python module
     */
    protected Value importPythonModule(String moduleName) {
        String code = String.format("import %s\n%s", moduleName, moduleName);
        return evalPython(code);
    }
    
    /**
     * Convert byte array to Python bytes
     */
    protected Value toPythonBytes(byte[] data) {
        pythonBindings.putMember("_temp_bytes", data);
        return evalPython("bytes(_temp_bytes)");
    }
    
    /**
     * Convert Python bytes to Java byte array
     */
    protected byte[] fromPythonBytes(Value pythonBytes) {
        // Get the Python bytes object and convert to list
        Value bytesList = evalPython("list(" + pythonBytes.toString() + ")");
        int length = (int) bytesList.getArraySize();
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) bytesList.getArrayElement(i).asInt();
        }
        return result;
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
     * Check if Python module can be imported
     */
    protected boolean canImportModule(String moduleName) {
        try {
            evalPython("import " + moduleName);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== SM3 Digest Methods ==========
    
    /**
     * Compute SM3 hash using Java Bouncy Castle implementation.
     *
     * @param input String input
     * @return Hex-encoded hash
     */
    protected String computeJavaSM3(String input) throws Exception {
        return computeJavaSM3(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute SM3 hash using Java Bouncy Castle implementation.
     *
     * @param input Byte array input
     * @return Hex-encoded hash
     */
    protected String computeJavaSM3(byte[] input) throws Exception {
        SM3Digest digest = new SM3Digest();
        digest.update(input, 0, input.length);

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);

        return bytesToHex(result);
    }

    /**
     * Compute SM3 hash using Python implementation via GraalVM.
     *
     * @param input String input
     * @return Hex-encoded hash
     */
    protected String computePythonSM3(String input) throws Exception {
        return computePythonSM3(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute SM3 hash using Python implementation via GraalVM.
     *
     * @param input Byte array input
     * @return Hex-encoded hash
     */
    protected String computePythonSM3(byte[] input) throws Exception {
        // Store input data in context
        pythonBindings.putMember("_input_data", input);
        
        String pythonCode = """
            from sm_bc.digest.sm3_digest import SM3Digest
            
            digest = SM3Digest()
            digest.update(_input_data, 0, len(_input_data))
            
            result = bytearray(digest.get_digest_size())
            digest.do_final(result, 0)
            
            # Convert to hex
            ''.join(format(b, '02x') for b in result)
        """;
        
        Value result = evalPython(pythonCode);
        return result.asString();
    }
    
    // ========== SM2 Signature Methods ==========
    
    /**
     * Sign a message using Java Bouncy Castle SM2 implementation.
     *
     * @param message Message to sign
     * @param privateKeyHex Private key in hex format
     * @return Signature in hex format
     */
    protected String signWithJavaSM2(byte[] message, String privateKeyHex) throws Exception {
        // Get SM2 domain parameters from GMNamedCurves
        X9ECParameters sm2Params = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2Params.getCurve(),
                sm2Params.getG(),
                sm2Params.getN(),
                sm2Params.getH()
        );
        
        // Parse private key
        BigInteger d = new BigInteger(privateKeyHex, 16);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParams);
        
        // Create signer with random parameter
        SM2Signer signer = new SM2Signer();
        ParametersWithRandom paramsWithRandom = new ParametersWithRandom(privateKey, new SecureRandom());
        signer.init(true, paramsWithRandom);
        signer.update(message, 0, message.length);
        
        // Generate signature
        byte[] signature = signer.generateSignature();
        
        return bytesToHex(signature);
    }

    /**
     * Verify a signature using Java Bouncy Castle SM2 implementation.
     *
     * @param message Message that was signed
     * @param signatureHex Signature in hex format
     * @param publicKeyHex Public key in hex format (uncompressed format: 04 + x + y)
     * @return true if signature is valid
     */
    protected boolean verifyWithJavaSM2(byte[] message, String signatureHex, String publicKeyHex) throws Exception {
        // Get SM2 domain parameters from GMNamedCurves
        X9ECParameters sm2Params = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2Params.getCurve(),
                sm2Params.getG(),
                sm2Params.getN(),
                sm2Params.getH()
        );
        
        // Parse public key (uncompressed format: 04 + x + y)
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
        
        // Create verifier
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        
        // Verify signature
        byte[] signature = hexToBytes(signatureHex);
        return verifier.verifySignature(signature);
    }

    /**
     * Sign a message using Python SM2 implementation via GraalVM.
     *
     * @param message Message to sign
     * @param privateKeyHex Private key in hex format
     * @return Signature in hex format
     */
    protected String signWithPythonSM2(byte[] message, String privateKeyHex) throws Exception {
        pythonBindings.putMember("_message", message);
        pythonBindings.putMember("_private_key_hex", privateKeyHex);
        
        String pythonCode = """
            from sm_bc.crypto.params.ec_private_key_parameters import ECPrivateKeyParameters
            from sm_bc.crypto.params.parameters_with_random import ParametersWithRandom
            from sm_bc.crypto.signers.sm2_signer import SM2Signer
            from sm_bc.crypto.ec.custom_named_curves import CustomNamedCurves
            from sm_bc.math.secure_random import SecureRandom
            
            # Get SM2 domain parameters
            domain_params = CustomNamedCurves.get_by_name("sm2p256v1")
            
            # Parse private key
            d = int(_private_key_hex, 16)
            private_key = ECPrivateKeyParameters(d, domain_params)
            
            # Create signer
            signer = SM2Signer()
            random = SecureRandom()
            params_with_random = ParametersWithRandom(private_key, random)
            signer.init(True, params_with_random)
            signer.update(_message, 0, len(_message))
            
            # Generate signature
            signature = signer.generate_signature()
            
            # Convert to hex
            ''.join(format(b, '02x') for b in signature)
        """;
        
        Value result = evalPython(pythonCode);
        return result.asString();
    }

    /**
     * Verify a signature using Python SM2 implementation via GraalVM.
     *
     * @param message Message that was signed
     * @param signatureHex Signature in hex format
     * @param publicKeyHex Public key in hex format (uncompressed format: 04 + x + y)
     * @return true if signature is valid
     */
    protected boolean verifyWithPythonSM2(byte[] message, String signatureHex, String publicKeyHex) throws Exception {
        pythonBindings.putMember("_message", message);
        pythonBindings.putMember("_signature_hex", signatureHex);
        pythonBindings.putMember("_public_key_hex", publicKeyHex);
        
        String pythonCode = """
            from sm_bc.crypto.params.ec_public_key_parameters import ECPublicKeyParameters
            from sm_bc.crypto.signers.sm2_signer import SM2Signer
            from sm_bc.crypto.ec.custom_named_curves import CustomNamedCurves
            
            # Get SM2 domain parameters
            domain_params = CustomNamedCurves.get_by_name("sm2p256v1")
            
            # Parse public key (uncompressed format: 04 + x + y)
            if not _public_key_hex.startswith('04'):
                raise ValueError('Public key must be in uncompressed format (04 + x + y)')
            
            coord_len = (len(_public_key_hex) - 2) // 2
            x_hex = _public_key_hex[2:2 + coord_len]
            y_hex = _public_key_hex[2 + coord_len:]
            
            x = int(x_hex, 16)
            y = int(y_hex, 16)
            
            curve = domain_params.get_curve()
            q = curve.create_point(x, y)
            public_key = ECPublicKeyParameters(q, domain_params)
            
            # Parse signature
            signature = bytes.fromhex(_signature_hex)
            
            # Create verifier
            verifier = SM2Signer()
            verifier.init(False, public_key)
            verifier.update(_message, 0, len(_message))
            
            # Verify signature
            verifier.verify_signature(signature)
        """;
        
        Value result = evalPython(pythonCode);
        return result.asBoolean();
    }
    
    /**
     * Check if GraalVM Python support is available
     * @return true if GraalVM Python is available, false otherwise
     */
    protected static boolean isGraalVMPythonAvailable() {
        try {
            Context testContext = Context.newBuilder("python")
                    .allowAllAccess(true)
                    .build();
            testContext.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
