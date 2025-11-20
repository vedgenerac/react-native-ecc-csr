package com.ecccsr;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;

/**
 * CSRModule - Generates ECC key pairs in Android Keystore and creates
 * Certificate Signing Requests (CSR)
 * 
 * SECURITY NOTE: Private keys are generated and stored in AndroidKeyStore and
 * NEVER leave the hardware.
 * They cannot be exported or accessed directly - only used for signing
 * operations.
 */
public class CSRModule extends ReactContextBaseJavaModule {
    private static final String TAG = "CSRModule";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";

    // Default alias - can be overridden by passing alias to methods
    private static final String DEFAULT_ALIAS = "GENERAC_PWRVIEW_ECC_KEY_ALIAS";

    /**
     * Configuration for ECC curves
     */
    private static class CurveConfig {
        String displayName; // User-friendly name (P-256, P-384, P-521)
        String javaName; // Java curve name (secp256r1, secp384r1, secp521r1)
        String digestAlgorithm; // Digest algorithm (SHA256, SHA384, SHA512)
        String signatureAlgorithm; // Full signature algorithm name
        int keySize; // Key size in bits

        CurveConfig(String displayName, String javaName, String digestAlgorithm, String signatureAlgorithm,
                int keySize) {
            this.displayName = displayName;
            this.javaName = javaName;
            this.digestAlgorithm = digestAlgorithm;
            this.signatureAlgorithm = signatureAlgorithm;
            this.keySize = keySize;
        }
    }

    /**
     * Validates curve name and returns configuration
     * 
     * @param curveName User-provided curve name (P-256, P-384, P-521)
     * @return CurveConfig with validated parameters
     * @throws Exception if curve name is invalid
     */
    private CurveConfig validateAndGetCurveConfig(String curveName) throws Exception {
        if (curveName == null || curveName.isEmpty()) {
            curveName = "P-256";
        }

        // Normalize curve name (remove spaces, convert to uppercase)
        curveName = curveName.trim().toUpperCase();

        switch (curveName) {
            case "P-256":
            case "P256":
            case "SECP256R1":
                return new CurveConfig("P-256", "secp256r1", "SHA256", "SHA256withECDSA", 256);

            case "P-384":
            case "P384":
            case "SECP384R1":
                return new CurveConfig("P-384", "secp384r1", "SHA384", "SHA384withECDSA", 384);

            case "P-521":
            case "P521":
            case "SECP521R1":
                return new CurveConfig("P-521", "secp521r1", "SHA512", "SHA512withECDSA", 521);

            default:
                throw new Exception("Invalid curve name: " + curveName +
                        ". Supported curves: P-256, P-384, P-521");
        }
    }

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        Log.d(TAG, "CSRModule initialized");
    }

    @Override
    public String getName() {
        return "CSRModule";
    }

    /**
     * Generates a Certificate Signing Request (CSR) using the private key from
     * Android Keystore
     * 
     * If the key pair doesn't exist, it will be automatically generated.
     * 
     * @param alias              The keystore alias where the private key is stored
     * @param curve              The elliptic curve to use: "P-256", "P-384", or
     *                           "P-521" (defaults to "P-256")
     * @param cn                 Common Name
     * @param userId             User ID
     * @param country            Country (2-letter code)
     * @param state              State or Province
     * @param locality           City or Locality
     * @param organization       Organization Name
     * @param organizationalUnit Organizational Unit
     * @param promise            Promise to resolve with CSR in PEM format or reject
     *                           with error
     * 
     *                           SECURITY: The private key never leaves the keystore
     *                           - it's only used for signing the CSR.
     */
    @ReactMethod
    public void generateCSR(
            String alias,
            String curve,
            String cn,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            Promise promise) {
        try {
            // Use provided alias or default
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            // Validate and normalize curve parameter
            String curveName = (curve != null && !curve.isEmpty()) ? curve : "P-256";
            CurveConfig curveConfig = validateAndGetCurveConfig(curveName);

            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Generating Certificate Signing Request (CSR)");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Alias: " + keyAlias);
            Log.d(TAG, "║ Curve: " + curveName + " (" + curveConfig.javaName + ")");
            Log.d(TAG, "║ Key Size: " + curveConfig.keySize + " bits");
            Log.d(TAG, "║ Signature Algorithm: " + curveConfig.signatureAlgorithm);
            Log.d(TAG, "║ CN: " + (cn != null ? cn : "null"));
            Log.d(TAG, "║ UID: " + (userId != null ? userId : "null"));
            Log.d(TAG, "║ C: " + (country != null ? country : "null"));
            Log.d(TAG, "║ ST: " + (state != null ? state : "null"));
            Log.d(TAG, "║ L: " + (locality != null ? locality : "null"));
            Log.d(TAG, "║ O: " + (organization != null ? organization : "null"));
            Log.d(TAG, "║ OU: " + (organizationalUnit != null ? organizationalUnit : "null"));
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            // Load Android Keystore
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Loading Android Keystore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore keyStore = null;
            try {
                keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
                Log.d(TAG, "  ✓ KeyStore.getInstance() successful");
                Log.d(TAG, "  ✓ Provider: " + KEYSTORE_PROVIDER);
                Log.d(TAG, "  ✓ KeyStore type: " + keyStore.getType());
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to get KeyStore instance: " + e.getMessage());
                e.printStackTrace();
                throw new Exception("Failed to get KeyStore instance: " + e.getMessage(), e);
            }

            try {
                keyStore.load(null);
                Log.d(TAG, "  ✓ KeyStore loaded successfully");
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to load KeyStore: " + e.getMessage());
                e.printStackTrace();
                throw new Exception("Failed to load KeyStore: " + e.getMessage(), e);
            }

            // List all aliases in keystore for debugging
            try {
                java.util.Enumeration<String> aliases = keyStore.aliases();
                Log.d(TAG, "  Available aliases in keystore:");
                int count = 0;
                while (aliases.hasMoreElements()) {
                    String existingAlias = aliases.nextElement();
                    Log.d(TAG, "    [" + count + "] " + existingAlias);
                    count++;
                }
                if (count == 0) {
                    Log.d(TAG, "    (no aliases found - keystore is empty)");
                }
            } catch (Exception e) {
                Log.w(TAG, "  ⚠️ Could not list keystore aliases: " + e.getMessage());
            }

            // Check if key exists, if not generate it automatically
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 2: Checking for Existing Key Pair");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            boolean aliasExists = false;
            try {
                aliasExists = keyStore.containsAlias(keyAlias);
                Log.d(TAG, "  ✓ containsAlias() check complete");
                Log.d(TAG, "  ✓ Key pair exists: " + aliasExists);
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to check alias: " + e.getMessage());
                e.printStackTrace();
                throw new Exception("Failed to check if alias exists: " + e.getMessage(), e);
            }

            if (!aliasExists) {
                Log.w(TAG, "  ⚠️ Private key not found with alias: " + keyAlias);
                Log.d(TAG, "  🔑 Auto-generating ECC key pair...");

                // Generate key pair automatically with specified curve
                try {
                    generateKeyPairInternal(keyAlias, curveConfig);
                    Log.i(TAG, "  ✓ Key pair auto-generated successfully");
                } catch (Exception e) {
                    Log.e(TAG, "  ❌ Failed to auto-generate key pair: " + e.getMessage());
                    e.printStackTrace();
                    throw new Exception("Failed to auto-generate key pair: " + e.getMessage(), e);
                }
            } else {
                Log.d(TAG, "  ✓ Found existing private key with alias: " + keyAlias);
            }

            // Get private key (stays in keystore, only a reference)
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Retrieving Private Key from Keystore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            PrivateKey privateKey = null;
            try {
                Log.d(TAG, "  Calling keyStore.getKey(\"" + keyAlias + "\", null)...");
                privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                Log.d(TAG, "  ✓ getKey() call successful");
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to retrieve key: " + e.getMessage());
                Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
                e.printStackTrace();
                throw new Exception("Failed to retrieve private key from keystore: " + e.getMessage(), e);
            }

            if (privateKey == null) {
                Log.e(TAG, "  ❌ Private key is null after retrieval");
                throw new Exception("Failed to retrieve private key from keystore - returned null");
            }

            Log.d(TAG, "  ✓ Private key reference obtained (key remains in hardware)");
            Log.d(TAG, "  ✓ Private key class: " + privateKey.getClass().getName());
            Log.d(TAG, "  ✓ Algorithm: " + privateKey.getAlgorithm());

            String format = privateKey.getFormat();
            if (format == null) {
                Log.d(TAG, "  ✓ Format: null (GOOD - hardware-backed, cannot export)");
            } else {
                Log.w(TAG, "  ⚠️ Format: " + format + " (key may be exportable!)");
            }

            byte[] encoded = privateKey.getEncoded();
            if (encoded == null) {
                Log.d(TAG, "  ✓ Encoded: null (GOOD - hardware-backed)");
            } else {
                Log.w(TAG, "  ⚠️ Encoded length: " + encoded.length + " bytes (key is exportable!)");
            }

            // Get public key from certificate
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 4: Retrieving Public Key from Certificate");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            java.security.cert.Certificate certificate = null;
            try {
                Log.d(TAG, "  Calling keyStore.getCertificate(\"" + keyAlias + "\")...");
                certificate = keyStore.getCertificate(keyAlias);
                Log.d(TAG, "  ✓ getCertificate() call successful");
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to retrieve certificate: " + e.getMessage());
                Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
                e.printStackTrace();
                throw new Exception("Failed to retrieve certificate from keystore: " + e.getMessage(), e);
            }

            if (certificate == null) {
                Log.e(TAG, "  ❌ Certificate is null");
                throw new Exception("Failed to retrieve certificate from keystore - returned null");
            }

            Log.d(TAG, "  ✓ Certificate retrieved");
            Log.d(TAG, "  ✓ Certificate type: " + certificate.getType());
            Log.d(TAG, "  ✓ Certificate class: " + certificate.getClass().getName());

            PublicKey publicKey = null;
            try {
                Log.d(TAG, "  Calling certificate.getPublicKey()...");
                publicKey = certificate.getPublicKey();
                Log.d(TAG, "  ✓ getPublicKey() call successful");
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to get public key from certificate: " + e.getMessage());
                Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
                e.printStackTrace();
                throw new Exception("Failed to get public key from certificate: " + e.getMessage(), e);
            }

            if (publicKey == null) {
                Log.e(TAG, "  ❌ Public key is null");
                throw new Exception("Failed to retrieve public key from keystore - returned null");
            }

            Log.d(TAG, "  ✓ Public key retrieved");
            Log.d(TAG, "  ✓ Public key class: " + publicKey.getClass().getName());
            Log.d(TAG, "  ✓ Algorithm: " + publicKey.getAlgorithm());

            byte[] publicKeyEncoded = publicKey.getEncoded();
            if (publicKeyEncoded != null) {
                Log.d(TAG, "  ✓ Public key encoded length: " + publicKeyEncoded.length + " bytes");
                // Log first few bytes for debugging
                StringBuilder hexString = new StringBuilder();
                for (int i = 0; i < Math.min(16, publicKeyEncoded.length); i++) {
                    hexString.append(String.format("%02X ", publicKeyEncoded[i]));
                }
                Log.d(TAG, "  ✓ Public key first bytes: " + hexString.toString() + "...");
            } else {
                Log.e(TAG, "  ❌ Public key encoded is null!");
                throw new Exception("Public key encoded is null - cannot create CSR");
            }

            // Create CSR
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 5: Creating CSR");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            String csr = null;
            try {
                csr = createCSR(cn, userId, country, state, locality, organization,
                        organizationalUnit, privateKey, publicKey, curveConfig.signatureAlgorithm);
                Log.d(TAG, "  ✓ createCSR() completed successfully");
            } catch (Exception e) {
                Log.e(TAG, "  ❌ CSR creation failed: " + e.getMessage());
                Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
                e.printStackTrace();
                throw new Exception("Failed to create CSR: " + e.getMessage(), e);
            }

            if (csr == null || csr.isEmpty()) {
                Log.e(TAG, "  ❌ CSR is null or empty");
                throw new Exception("CSR creation returned null or empty string");
            }

            Log.i(TAG, "");
            Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.i(TAG, "║ ✓✓✓ CSR Generated Successfully");
            Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.i(TAG, "║ CSR Length: " + csr.length() + " characters");
            Log.i(TAG, "║ Format: PEM (PKCS#10)");
            Log.i(TAG, "║ Signature Algorithm: SHA256withECDSA");
            Log.i(TAG, "║ Private key NEVER left the hardware keystore");
            Log.i(TAG, "╚════════════════════════════════════════════════════════════════");

            // Log CSR preview (first and last lines)
            String[] lines = csr.split("\n");
            if (lines.length > 0) {
                Log.d(TAG, "CSR Preview:");
                Log.d(TAG, "  First line: " + lines[0]);
                if (lines.length > 1) {
                    Log.d(TAG, "  Second line: " + lines[1].substring(0, Math.min(40, lines[1].length())) + "...");
                }
                if (lines.length > 2) {
                    Log.d(TAG, "  Last line: " + lines[lines.length - 1]);
                }
            }

            promise.resolve(csr);

        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ CSR GENERATION FAILED");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Error: " + e.getMessage());
            Log.e(TAG, "║ Type: " + e.getClass().getName());

            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
                Log.e(TAG, "║ Cause Type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();

            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }

            promise.reject("CSR_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Generates an ECC key pair in Android Keystore
     * 
     * NOTE: You typically don't need to call this method directly.
     * generateCSR() will automatically generate the key pair if it doesn't exist.
     * 
     * Use this method only if you want to:
     * - Pre-generate keys before creating a CSR
     * - Explicitly control when keys are generated
     * - Regenerate keys by deleting and creating new ones
     * 
     * @param alias   The keystore alias to store the key pair under
     * @param curve   The elliptic curve to use: "P-256", "P-384", or "P-521"
     *                (defaults to "P-256")
     * @param promise Promise to resolve with success message or reject with error
     * 
     *                IMPORTANT: The private key is generated in hardware-backed
     *                storage and cannot be exported.
     */
    @ReactMethod
    public void generateECCKeyPair(String alias, String curve, Promise promise) {
        try {
            // Use provided alias or default
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            // Validate and normalize curve parameter
            String curveName = (curve != null && !curve.isEmpty()) ? curve : "P-256";
            CurveConfig curveConfig = validateAndGetCurveConfig(curveName);

            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Generating ECC Key Pair (Explicit Call)");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Alias: " + keyAlias);
            Log.d(TAG, "║ Curve: " + curveName + " (" + curveConfig.javaName + ")");
            Log.d(TAG, "║ Key Size: " + curveConfig.keySize + " bits");
            Log.d(TAG, "║ Note: generateCSR() can auto-generate keys if needed");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            // Check if key already exists
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (keyStore.containsAlias(keyAlias)) {
                Log.w(TAG, "⚠️ Key with alias '" + keyAlias + "' already exists. Deleting old key...");
                keyStore.deleteEntry(keyAlias);
                Log.d(TAG, "✓ Old key deleted");
            }

            // Generate the key pair
            generateKeyPairInternal(keyAlias, curveConfig);

            Log.i(TAG, "✓✓✓ ECC Key Pair Generated Successfully");

            promise.resolve("ECC key pair generated successfully with alias: " + keyAlias + ", curve: " + curveName);

        } catch (Exception e) {
            Log.e(TAG, "❌ Failed to generate ECC key pair: " + e.getMessage());
            e.printStackTrace();
            promise.reject("ECC_ERROR", "Failed to generate ECC key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if a key pair exists in the keystore
     * 
     * @param alias   The keystore alias to check
     * @param promise Promise to resolve with boolean (true if exists, false
     *                otherwise)
     */
    @ReactMethod
    public void keyPairExists(String alias, Promise promise) {
        try {
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            boolean exists = keyStore.containsAlias(keyAlias);
            Log.d(TAG, "Key pair exists for alias '" + keyAlias + "': " + exists);

            promise.resolve(exists);

        } catch (Exception e) {
            Log.e(TAG, "Error checking key pair existence: " + e.getMessage());
            promise.reject("KEYSTORE_ERROR", "Failed to check key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes a key pair from the keystore
     * 
     * @param alias   The keystore alias to delete
     * @param promise Promise to resolve with success message or reject with error
     */
    @ReactMethod
    public void deleteKeyPair(String alias, Promise promise) {
        try {
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(keyAlias)) {
                Log.w(TAG, "Key pair with alias '" + keyAlias + "' does not exist");
                promise.resolve("Key pair does not exist");
                return;
            }

            keyStore.deleteEntry(keyAlias);
            Log.i(TAG, "✓ Key pair deleted: " + keyAlias);

            promise.resolve("Key pair deleted successfully: " + keyAlias);

        } catch (Exception e) {
            Log.e(TAG, "Error deleting key pair: " + e.getMessage());
            promise.reject("KEYSTORE_ERROR", "Failed to delete key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the public key in PEM format
     * 
     * @param alias   The keystore alias
     * @param promise Promise to resolve with public key PEM or reject with error
     */
    @ReactMethod
    public void getPublicKey(String alias, Promise promise) {
        try {
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(keyAlias)) {
                throw new Exception("Key pair not found with alias: " + keyAlias);
            }

            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

            // Convert to PEM format
            StringWriter stringWriter = new StringWriter();
            try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            }

            String publicKeyPem = stringWriter.toString();
            Log.d(TAG, "✓ Public key retrieved for alias: " + keyAlias);

            promise.resolve(publicKeyPem);

        } catch (Exception e) {
            Log.e(TAG, "Error getting public key: " + e.getMessage());
            promise.reject("KEYSTORE_ERROR", "Failed to get public key: " + e.getMessage(), e);
        }
    }

    /**
     * Internal method to generate ECC key pair
     * Used by both generateECCKeyPair() and generateCSR()
     * 
     * @param keyAlias    The keystore alias to use
     * @param curveConfig The curve configuration
     * @throws Exception if key generation fails
     */
    private void generateKeyPairInternal(String keyAlias, CurveConfig curveConfig) throws Exception {
        Log.d(TAG, "  ┌───────────────────────────────────────────────────────────");
        Log.d(TAG, "  │ Generating ECC key pair in AndroidKeyStore");
        Log.d(TAG, "  └───────────────────────────────────────────────────────────");
        Log.d(TAG, "    Alias: " + keyAlias);
        Log.d(TAG, "    Curve: " + curveConfig.displayName + " (" + curveConfig.javaName + ")");
        Log.d(TAG, "    Key Size: " + curveConfig.keySize + " bits");
        Log.d(TAG, "    Digest: " + curveConfig.digestAlgorithm);
        Log.d(TAG, "    Provider: " + KEYSTORE_PROVIDER);

        // Generate key pair in AndroidKeyStore
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    KEYSTORE_PROVIDER);
            Log.d(TAG, "    ✓ KeyPairGenerator obtained");

            // Select digest algorithms based on curve
            String[] digests;
            if (curveConfig.displayName.equals("P-256")) {
                digests = new String[] { KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512 };
            } else if (curveConfig.displayName.equals("P-384")) {
                digests = new String[] { KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512 };
            } else { // P-521
                digests = new String[] { KeyProperties.DIGEST_SHA512 };
            }

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(curveConfig.javaName))
                    .setDigests(digests)
                    .setUserAuthenticationRequired(false) // No biometric/PIN required for signing
                    .build();
            Log.d(TAG, "    ✓ KeyGenParameterSpec built");

            keyPairGenerator.initialize(spec);
            Log.d(TAG, "    ✓ KeyPairGenerator initialized");

            keyPairGenerator.generateKeyPair();
            Log.d(TAG, "    ✓ Key pair generated");

        } catch (Exception e) {
            Log.e(TAG, "    ❌ Key pair generation failed: " + e.getMessage());
            Log.e(TAG, "    ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to generate key pair: " + e.getMessage(), e);
        }

        Log.d(TAG, "    ✓ Key pair generated and stored in hardware");
        Log.d(TAG, "    ✓ Alias: " + keyAlias);
        Log.d(TAG, "    ✓ Private key is hardware-backed and cannot be exported");
        Log.d(TAG, "    ✓ Public key can be accessed via keystore certificate");
    }

    /**
     * Creates a PKCS#10 Certificate Signing Request
     * 
     * @param cn                 Common Name
     * @param userId             User ID
     * @param country            Country code
     * @param state              State/Province
     * @param locality           City
     * @param organization       Organization name
     * @param organizationalUnit Department/Unit
     * @param privateKey         Private key (reference only - stays in keystore)
     * @param publicKey          Public key
     * @param signatureAlgorithm Signature algorithm to use (e.g., SHA256withECDSA)
     * @return CSR in PEM format
     * @throws Exception if CSR creation fails
     */
    private String createCSR(
            String cn,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            PrivateKey privateKey,
            PublicKey publicKey,
            String signatureAlgorithm) throws Exception {

        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Building CSR Subject (X.500 Name)");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        // Build X.500Name with subject information
        X500NameBuilder nameBuilder = null;
        try {
            nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            Log.d(TAG, "  ✓ X500NameBuilder created");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to create X500NameBuilder: " + e.getMessage());
            throw new Exception("Failed to create X500NameBuilder: " + e.getMessage(), e);
        }

        int fieldCount = 0;

        if (cn != null && !cn.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.CN, cn);
                Log.d(TAG, "  ✓ CN: " + cn);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add CN: " + e.getMessage());
                throw new Exception("Failed to add CN to subject: " + e.getMessage(), e);
            }
        }
        if (userId != null && !userId.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.UID, userId);
                Log.d(TAG, "  ✓ UID: " + userId);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add UID: " + e.getMessage());
                throw new Exception("Failed to add UID to subject: " + e.getMessage(), e);
            }
        }
        if (country != null && !country.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.C, country);
                Log.d(TAG, "  ✓ C: " + country);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add C: " + e.getMessage());
                throw new Exception("Failed to add Country to subject: " + e.getMessage(), e);
            }
        }
        if (state != null && !state.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.ST, state);
                Log.d(TAG, "  ✓ ST: " + state);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add ST: " + e.getMessage());
                throw new Exception("Failed to add State to subject: " + e.getMessage(), e);
            }
        }
        if (locality != null && !locality.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.L, locality);
                Log.d(TAG, "  ✓ L: " + locality);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add L: " + e.getMessage());
                throw new Exception("Failed to add Locality to subject: " + e.getMessage(), e);
            }
        }
        if (organization != null && !organization.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.O, organization);
                Log.d(TAG, "  ✓ O: " + organization);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add O: " + e.getMessage());
                throw new Exception("Failed to add Organization to subject: " + e.getMessage(), e);
            }
        }
        if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
            try {
                nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
                Log.d(TAG, "  ✓ OU: " + organizationalUnit);
                fieldCount++;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Failed to add OU: " + e.getMessage());
                throw new Exception("Failed to add OU to subject: " + e.getMessage(), e);
            }
        }

        Log.d(TAG, "  ✓ Total fields added: " + fieldCount);

        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Converting Public Key to SubjectPublicKeyInfo");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        // Convert public key to SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjectPublicKeyInfo = null;
        try {
            byte[] publicKeyEncoded = publicKey.getEncoded();
            Log.d(TAG, "  ✓ Public key encoded: " + publicKeyEncoded.length + " bytes");

            subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyEncoded);
            Log.d(TAG, "  ✓ SubjectPublicKeyInfo created successfully");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to create SubjectPublicKeyInfo: " + e.getMessage());
            Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to convert public key to SubjectPublicKeyInfo: " + e.getMessage(), e);
        }

        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Building PKCS#10 CSR");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        // Build PKCS#10 CSR
        PKCS10CertificationRequestBuilder csrBuilder = null;
        try {
            csrBuilder = new PKCS10CertificationRequestBuilder(
                    nameBuilder.build(), subjectPublicKeyInfo);
            Log.d(TAG, "  ✓ CSR builder created");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to create CSR builder: " + e.getMessage());
            Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to create CSR builder: " + e.getMessage(), e);
        }

        // Create content signer using private key (key stays in hardware)
        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Creating Content Signer");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        ContentSigner contentSigner = null;
        try {
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
            Log.d(TAG, "  ✓ JcaContentSignerBuilder created (" + signatureAlgorithm + ")");

            contentSigner = signerBuilder.build(privateKey);
            Log.d(TAG, "  ✓ Content signer created (using hardware-backed private key)");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to create content signer: " + e.getMessage());
            Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to create content signer: " + e.getMessage(), e);
        }

        // Build the CSR
        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Signing CSR");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        PKCS10CertificationRequest csr = null;
        try {
            csr = csrBuilder.build(contentSigner);
            Log.d(TAG, "  ✓ CSR signed successfully");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to sign CSR: " + e.getMessage());
            Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to sign CSR: " + e.getMessage(), e);
        }

        Log.d(TAG, "");
        Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
        Log.d(TAG, "│ Converting CSR to PEM Format");
        Log.d(TAG, "└─────────────────────────────────────────────────────────────");

        // Convert to PEM format
        String pemCsr = null;
        try {
            byte[] csrEncoded = csr.getEncoded();
            Log.d(TAG, "  ✓ CSR encoded: " + csrEncoded.length + " bytes");

            StringWriter stringWriter = new StringWriter();
            try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csrEncoded));
            }

            pemCsr = stringWriter.toString();
            Log.d(TAG, "  ✓ CSR converted to PEM format");
            Log.d(TAG, "  ✓ CSR length: " + pemCsr.length() + " characters");
        } catch (Exception e) {
            Log.e(TAG, "  ❌ Failed to convert CSR to PEM: " + e.getMessage());
            Log.e(TAG, "  ❌ Exception type: " + e.getClass().getName());
            throw new Exception("Failed to convert CSR to PEM format: " + e.getMessage(), e);
        }

        return pemCsr;
    }
}
