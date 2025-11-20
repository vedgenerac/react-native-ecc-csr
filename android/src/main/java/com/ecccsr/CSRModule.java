package com.ecccsr;

import android.util.Base64;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class CSRModule extends ReactContextBaseJavaModule {

    private static final String MODULE_NAME = "CSRModule";

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

            // Validate curve
            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            // Generate EC key pair with specified curve
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
            keyPairGenerator.initialize(ecSpec);
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
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(privateKey);

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Convert CSR to PEM format
            StringWriter csrWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            String csrPem = csrWriter.toString();

            // Convert private key to PEM format
            StringWriter keyWriter = new StringWriter();
            JcaPEMWriter keyPemWriter = new JcaPEMWriter(keyWriter);
            keyPemWriter.writeObject(keyPair);
            keyPemWriter.close();
            String privateKeyPem = keyWriter.toString();

            // Prepare response
            com.facebook.react.bridge.WritableMap response = 
                com.facebook.react.bridge.Arguments.createMap();
            response.putString("csr", csrPem);
            response.putString("privateKey", privateKeyPem);
            response.putString("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));

            promise.resolve(response);

        } catch (Exception e) {
            promise.reject("CSR_GENERATION_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void generateKeyPair(ReadableMap params, Promise promise) {
        try {
            String curve = params.hasKey("curve") ? params.getString("curve") : "secp384r1"; // P-384 default

            // Validate curve
            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            // Generate EC key pair with specified curve
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
            keyPairGenerator.initialize(ecSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Convert to PEM format
            StringWriter keyWriter = new StringWriter();
            JcaPEMWriter keyPemWriter = new JcaPEMWriter(keyWriter);
            keyPemWriter.writeObject(keyPair);
            keyPemWriter.close();
            String privateKeyPem = keyWriter.toString();

            // Get public key as Base64
            String publicKeyBase64 = Base64.encodeToString(
                keyPair.getPublic().getEncoded(), 
                Base64.NO_WRAP
            );

            com.facebook.react.bridge.WritableMap response = 
                com.facebook.react.bridge.Arguments.createMap();
            response.putString("privateKey", privateKeyPem);
            response.putString("publicKey", publicKeyBase64);

            promise.resolve(response);

        } catch (Exception e) {
            promise.reject("KEY_GENERATION_ERROR", "Failed to generate key pair: " + e.getMessage(), e);
        }
    }
}
