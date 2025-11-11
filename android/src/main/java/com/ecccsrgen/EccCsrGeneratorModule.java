package com.ecccsrgen;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

public class EccCsrGeneratorModule extends ReactContextBaseJavaModule {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    
    static {
        Security.removeProvider("BC");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public EccCsrGeneratorModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "EccCsrGenerator";
    }

    @ReactMethod
    public void generateCSR(ReadableMap options, Promise promise) {
        try {
            String commonName = options.getString("commonName");
            String serialNumber = options.hasKey("serialNumber") ? options.getString("serialNumber") : "";
            String country = options.hasKey("country") ? options.getString("country") : "";
            String state = options.hasKey("state") ? options.getString("state") : "";
            String locality = options.hasKey("locality") ? options.getString("locality") : "";
            String organization = options.hasKey("organization") ? options.getString("organization") : "";
            String organizationalUnit = options.hasKey("organizationalUnit") ? options.getString("organizationalUnit") : "";
            String ipAddress = options.hasKey("ipAddress") ? options.getString("ipAddress") : "";
            String curve = options.hasKey("curve") ? options.getString("curve") : "P-384";
            String keyAlias = options.hasKey("keyAlias") ? options.getString("keyAlias") : "ECC_CSR_KEY";

            if (commonName == null || commonName.isEmpty()) {
                promise.reject("INVALID_PARAMS", "commonName is required");
                return;
            }

            // Map curve names to Java EC spec names
            String curveName = getCurveSpec(curve);

            // Generate ECC key pair in Android KeyStore
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    ANDROID_KEYSTORE
            );

            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(curveName))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                    .build();

            keyPairGenerator.initialize(keyGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Build subject DN
            X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            
            if (!country.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.C, country);
            }
            if (!state.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.ST, state);
            }
            if (!locality.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.L, locality);
            }
            if (!organization.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.O, organization);
            }
            if (!organizationalUnit.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.OU, organizationalUnit);
            }
            
            // Add CN with serialNumber if provided
            if (!serialNumber.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.CN, commonName + "/serialNumber=" + serialNumber);
            } else {
                subjectBuilder.addRDN(BCStyle.CN, commonName);
            }

            X500Name subject = subjectBuilder.build();

            // Create public key info
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            // Build CSR
            PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);

            // Add extensions
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

            // Key Usage extension (critical) - Digital Signature and Key Agreement
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            extensionsGenerator.addExtension(Extension.keyUsage, true, keyUsage);

            // Extended Key Usage - TLS Web Client Authentication
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
            extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

            // Subject Alternative Name - IP Address
            if (!ipAddress.isEmpty()) {
                try {
                    InetAddress inetAddress = InetAddress.getByName(ipAddress);
                    // Wrap IP address bytes in DEROctetString for BouncyCastle
                    GeneralName generalName = new GeneralName(GeneralName.iPAddress, new DEROctetString(inetAddress.getAddress()));
                    GeneralNames subjectAltNames = new GeneralNames(generalName);
                    extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
                } catch (Exception e) {
                    // Invalid IP address, skip
                }
            }

            // Add extensions to CSR
            csrBuilder.addAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensionsGenerator.generate()
            );

            // Sign the CSR with ECDSA-SHA256
            // Create custom ContentSigner for Android KeyStore keys
            ContentSigner signer = new ContentSigner() {
                private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    // ecdsa-with-SHA256 OID: 1.2.840.10045.4.3.2
                    return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
                }

                @Override
                public java.io.OutputStream getOutputStream() {
                    return outputStream;
                }

                @Override
                public byte[] getSignature() {
                    try {
                        java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
                        signature.initSign(keyPair.getPrivate());
                        signature.update(outputStream.toByteArray());
                        return signature.sign();
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to sign", e);
                    }
                }
            };

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Convert to PEM format
            String csrPem = convertToPEM(csr.getEncoded(), "CERTIFICATE REQUEST");
            String publicKeyPem = convertToPEM(keyPair.getPublic().getEncoded(), "PUBLIC KEY");

            WritableMap result = new WritableNativeMap();
            result.putString("csr", csrPem);
            result.putString("publicKey", publicKeyPem);

            promise.resolve(result);

        } catch (Exception e) {
            promise.reject("CSR_GENERATION_FAILED", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void getPublicKey(String keyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            if (!keyStore.containsAlias(keyAlias)) {
                promise.reject("KEY_NOT_FOUND", "Key pair not found");
                return;
            }

            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (certificate != null) {
                PublicKey publicKey = certificate.getPublicKey();
                String publicKeyPem = convertToPEM(publicKey.getEncoded(), "PUBLIC KEY");
                promise.resolve(publicKeyPem);
            } else {
                // Try to get from key entry
                KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                    PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
                    String publicKeyPem = convertToPEM(publicKey.getEncoded(), "PUBLIC KEY");
                    promise.resolve(publicKeyPem);
                } else {
                    promise.reject("PUBLIC_KEY_FAILED", "Failed to extract public key");
                }
            }
        } catch (Exception e) {
            promise.reject("GET_PUBLIC_KEY_FAILED", "Failed to get public key: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void deleteKeyPair(String keyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias);
            }

            promise.resolve(true);
        } catch (Exception e) {
            promise.reject("DELETE_FAILED", "Failed to delete key pair: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void hasKeyPair(String keyAlias, Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            promise.resolve(keyStore.containsAlias(keyAlias));
        } catch (Exception e) {
            promise.resolve(false);
        }
    }

    private String getCurveSpec(String curve) {
        switch (curve) {
            case "P-256":
                return "secp256r1";
            case "P-384":
                return "secp384r1";
            case "P-521":
                return "secp521r1";
            default:
                return "secp384r1"; // Default to P-384
        }
    }

    private String convertToPEM(byte[] encoded, String type) {
        String base64 = Base64.encodeToString(encoded, Base64.NO_WRAP);
        
        // Split into 64-character lines
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(type).append("-----\n");
        
        int index = 0;
        while (index < base64.length()) {
            int endIndex = Math.min(index + 64, base64.length());
            pem.append(base64.substring(index, endIndex)).append("\n");
            index = endIndex;
        }
        
        pem.append("-----END ").append(type).append("-----");
        
        return pem.toString();
    }
}
