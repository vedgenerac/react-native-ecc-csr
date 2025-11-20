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
import java.io.StringWriter;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * CSRModule - Generates ECC Certificate Signing Requests with proper X.509v3
 * extensions
 * for mTLS client authentication
 * 
 * CRITICAL: This version INCLUDES Key Usage and Extended Key Usage extensions
 */
public class CSRModule extends ReactContextBaseJavaModule {
    private static final String TAG = "CSRModule";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String DEFAULT_ALIAS = "ECC_CSR_KEY_ALIAS";

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "CSRModule";
    }

    /**
     * Generates ECC key pair in Android Keystore if it doesn't exist
     */
    private void generateKeyPairIfNeeded(String alias, String curve) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        if (!keyStore.containsAlias(alias)) {
            Log.d(TAG, "Generating new ECC key pair with alias: " + alias + ", curve: " + curve);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(curve))
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512)
                    .setUserAuthenticationRequired(false);

            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            Log.d(TAG, "✅ Key pair generated successfully");
        } else {
            Log.d(TAG, "Key pair already exists with alias: " + alias);
        }
    }

    /**
     * Generate CSR with X.509v3 extensions
     * 
     * @param alias              Keystore alias (use empty string for default)
     * @param curve              ECC curve: "secp256r1" (P-256), "secp384r1"
     *                           (P-384), or "secp521r1" (P-521)
     * @param cn                 Common Name
     * @param serialNumber       Serial Number
     * @param country            Country (2-letter code)
     * @param state              State
     * @param locality           City
     * @param organization       Organization
     * @param organizationalUnit Organizational Unit
     * @param promise            React Native promise
     */
    @ReactMethod
    public void generateCSR(
            String alias,
            String curve,
            String cn,
            String serialNumber,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            Promise promise) {

        try {
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;
            String eccCurve = (curve != null && !curve.isEmpty()) ? curve : "secp256r1";

            Log.d(TAG, "════════════════════════════════════════");
            Log.d(TAG, "Generating CSR with extensions");
            Log.d(TAG, "Alias: " + keyAlias);
            Log.d(TAG, "Curve: " + eccCurve);
            Log.d(TAG, "CN: " + cn);
            Log.d(TAG, "serialNumber: " + serialNumber);
            Log.d(TAG, "════════════════════════════════════════");

            // Generate key pair if needed
            generateKeyPairIfNeeded(keyAlias, eccCurve);

            // Load keystore and get keys
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

            if (privateKey == null || publicKey == null) {
                throw new Exception("Failed to retrieve keys from keystore");
            }

            // Build subject DN in proper order: C, ST, L, O, OU, CN, serialNumber
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            if (country != null && !country.isEmpty()) {
                nameBuilder.addRDN(BCStyle.C, country);
            }
            if (state != null && !state.isEmpty()) {
                nameBuilder.addRDN(BCStyle.ST, state);
            }
            if (locality != null && !locality.isEmpty()) {
                nameBuilder.addRDN(BCStyle.L, locality);
            }
            if (organization != null && !organization.isEmpty()) {
                nameBuilder.addRDN(BCStyle.O, organization);
            }
            if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
                nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
            }
            if (cn != null && !cn.isEmpty()) {
                nameBuilder.addRDN(BCStyle.CN, cn);
            }
            if (serialNumber != null && !serialNumber.isEmpty()) {
                nameBuilder.addRDN(BCStyle.SERIALNUMBER, serialNumber);
            }

            // Convert public key to SubjectPublicKeyInfo
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                    publicKey.getEncoded());

            // Create CSR builder
            PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                    nameBuilder.build(), subjectPublicKeyInfo);

            // ═══════════════════════════════════════════════════════════════
            // CRITICAL: Add X.509v3 Extensions for mTLS
            // ═══════════════════════════════════════════════════════════════

            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

            // 1. Key Usage: Digital Signature, Key Agreement (CRITICAL)
            KeyUsage keyUsage = new KeyUsage(
                    KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            extensionsGenerator.addExtension(
                    Extension.keyUsage,
                    true, // critical = true
                    keyUsage);
            Log.d(TAG, "✅ Added Key Usage: digitalSignature, keyAgreement (critical)");

            // 2. Extended Key Usage: TLS Web Client Authentication
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
                    KeyPurposeId.id_kp_clientAuth);
            extensionsGenerator.addExtension(
                    Extension.extendedKeyUsage,
                    false, // critical = false
                    extendedKeyUsage);
            Log.d(TAG, "✅ Added Extended Key Usage: clientAuth");

            Extensions extensions = extensionsGenerator.generate();

            // Add extensions as an attribute to the CSR
            csrBuilder.addAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensions);
            Log.d(TAG, "✅ Extensions added to CSR");

            // ═══════════════════════════════════════════════════════════════
            // Sign and build the CSR
            // ═══════════════════════════════════════════════════════════════

            // Determine signature algorithm based on curve
            String signatureAlgorithm;
            if (eccCurve.equals("secp256r1")) {
                signatureAlgorithm = "SHA256withECDSA";
            } else if (eccCurve.equals("secp384r1")) {
                signatureAlgorithm = "SHA384withECDSA";
            } else if (eccCurve.equals("secp521r1")) {
                signatureAlgorithm = "SHA512withECDSA";
            } else {
                signatureAlgorithm = "SHA256withECDSA"; // default
            }

            Log.d(TAG, "Using signature algorithm: " + signatureAlgorithm);

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
            ContentSigner signer = signerBuilder.build(privateKey);
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Convert to PEM format
            StringWriter stringWriter = new StringWriter();
            try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
            }

            String csrPem = stringWriter.toString();
            Log.d(TAG, "════════════════════════════════════════");
            Log.d(TAG, "✅ CSR Generated Successfully with Extensions!");
            Log.d(TAG, "════════════════════════════════════════");

            promise.resolve(csrPem);

        } catch (Exception e) {
            Log.e(TAG, "❌ CSR generation failed", e);
            promise.reject("CSR_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Delete key from keystore
     */
    @ReactMethod
    public void deleteKey(String alias, Promise promise) {
        try {
            String keyAlias = (alias != null && !alias.isEmpty()) ? alias : DEFAULT_ALIAS;

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias);
                Log.d(TAG, "✅ Deleted key with alias: " + keyAlias);
                promise.resolve("Key deleted successfully");
            } else {
                Log.w(TAG, "⚠️ Key not found with alias: " + keyAlias);
                promise.resolve("Key not found");
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Failed to delete key", e);
            promise.reject("DELETE_ERROR", "Failed to delete key: " + e.getMessage(), e);
        }
    }
}
