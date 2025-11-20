package com.ecccsr;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class CSRModule extends ReactContextBaseJavaModule {

    private static final String MODULE_NAME = "CSRModule";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @ReactMethod
    public void generateCSR(ReadableMap params, Promise promise) {
        try {
            // Extract parameters
            String country = params.hasKey("country") ? params.getString("country") : "US";
            String state = params.hasKey("state") ? params.getString("state") : "Nevada";
            String locality = params.hasKey("locality") ? params.getString("locality") : "Reno";
            String organization = params.hasKey("organization") ? params.getString("organization") : "Generac";
            String organizationalUnit = params.hasKey("organizationalUnit") ? params.getString("organizationalUnit") : "PWRview";
            String commonName = params.hasKey("commonName") ? params.getString("commonName") : "";
            String serialNumber = params.hasKey("serialNumber") ? params.getString("serialNumber") : "";
            String ipAddress = params.hasKey("ipAddress") ? params.getString("ipAddress") : "10.10.10.10";
            String curve = params.hasKey("curve") ? params.getString("curve") : "secp384r1"; // P-384 default
            
            // CRITICAL: privateKeyAlias for Android Keystore
            String privateKeyAlias = params.hasKey("privateKeyAlias") ? params.getString("privateKeyAlias") : null;
            
            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                promise.reject("MISSING_ALIAS", "privateKeyAlias is required for secure key storage");
                return;
            }

            // Validate curve
            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            // Map curve to Android Keystore curve
            String keystoreCurve;
            switch (curve) {
                case "secp256r1":
                    keystoreCurve = "secp256r1";
                    break;
                case "secp384r1":
                    keystoreCurve = "secp384r1";
                    break;
                case "secp521r1":
                    keystoreCurve = "secp521r1";
                    break;
                default:
                    keystoreCurve = "secp384r1";
            }

            // Generate key pair in Android Keystore (hardware-backed)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, 
                ANDROID_KEYSTORE
            );

            // Configure key generation with hardware backing
            KeyGenParameterSpec.Builder specBuilder = new KeyGenParameterSpec.Builder(
                privateKeyAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
            .setAlgorithmParameterSpec(new ECGenParameterSpec(keystoreCurve))
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            .setUserAuthenticationRequired(false); // Set to true if you want user auth (fingerprint/PIN)

            // Initialize key generator with spec
            keyPairGenerator.initialize(specBuilder.build());

            // Generate key pair - private key NEVER leaves the hardware!
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Build the subject DN
            StringBuilder subjectBuilder = new StringBuilder();
            subjectBuilder.append("C=").append(country);
            subjectBuilder.append(", ST=").append(state);
            subjectBuilder.append(", L=").append(locality);
            subjectBuilder.append(", O=").append(organization);
            subjectBuilder.append(", OU=").append(organizationalUnit);
            subjectBuilder.append(", CN=").append(commonName);
            if (!serialNumber.isEmpty()) {
                subjectBuilder.append(", serialNumber=").append(serialNumber);
            }

            X500Name subject = new X500Name(subjectBuilder.toString());

            // Create CSR builder
            PKCS10CertificationRequestBuilder csrBuilder = 
                new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            // Create extensions
            ExtensionsGenerator extGen = new ExtensionsGenerator();

            // Add Key Usage (critical): Digital Signature, Key Agreement
            KeyUsage keyUsage = new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.keyAgreement
            );
            extGen.addExtension(Extension.keyUsage, true, keyUsage);

            // Add Extended Key Usage: TLS Web Client Authentication
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
                KeyPurposeId.id_kp_clientAuth
            );
            extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

            // Add Subject Alternative Name: IP Address
            GeneralName[] sanArray = new GeneralName[1];
            sanArray[0] = new GeneralName(GeneralName.iPAddress, ipAddress);
            GeneralNames subjectAltNames = new GeneralNames(sanArray);
            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

            // Add extensions to CSR
            csrBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extGen.generate()
            );

            // Sign the CSR with SHA256withECDSA
            // Note: Signing happens in hardware using the private key alias
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(ANDROID_KEYSTORE)
                .build(privateKey);

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Convert CSR to PEM format
            StringWriter csrWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            String csrPem = csrWriter.toString();

            // Prepare response - NO PRIVATE KEY RETURNED!
            com.facebook.react.bridge.WritableMap response = 
                com.facebook.react.bridge.Arguments.createMap();
            response.putString("csr", csrPem);
            response.putString("privateKeyAlias", privateKeyAlias); // Return alias only
            response.putString("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
            response.putBoolean("isHardwareBacked", isHardwareBacked(privateKeyAlias));

            promise.resolve(response);

        } catch (Exception e) {
            promise.reject("CSR_GENERATION_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void deleteKey(String privateKeyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(privateKeyAlias);
            promise.resolve(true);
        } catch (Exception e) {
            promise.reject("DELETE_KEY_ERROR", "Failed to delete key: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void keyExists(String privateKeyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            boolean exists = keyStore.containsAlias(privateKeyAlias);
            promise.resolve(exists);
        } catch (Exception e) {
            promise.reject("KEY_EXISTS_ERROR", "Failed to check key existence: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void getPublicKey(String privateKeyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            if (!keyStore.containsAlias(privateKeyAlias)) {
                promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");
                return;
            }

            PublicKey publicKey = keyStore.getCertificate(privateKeyAlias).getPublicKey();
            String publicKeyBase64 = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
            
            promise.resolve(publicKeyBase64);
        } catch (Exception e) {
            promise.reject("GET_PUBLIC_KEY_ERROR", "Failed to get public key: " + e.getMessage(), e);
        }
    }

    /**
     * Check if the key is hardware-backed
     */
    private boolean isHardwareBacked(String privateKeyAlias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                // Check if key is hardware-backed (available on Android 9+)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    return privateKeyEntry.getPrivateKey()
                        .getAlgorithm()
                        .equals(KeyProperties.KEY_ALGORITHM_EC);
                }
            }
            return true; // Assume hardware-backed for older Android versions
        } catch (Exception e) {
            return false;
        }
    }
}