import CSRModule, { CSRParams } from 'react-native-ecc-csr';

/**
 * SECURE Example: Generate CSR with hardware-backed key storage
 * The private key NEVER leaves the Android Keystore hardware
 */
async function generateSecureCSR() {
    try {
        // IMPORTANT: Generate a unique alias for this device/certificate
        const privateKeyAlias = `pwrview_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const params: CSRParams = {
            country: "US",
            state: "Nevada",
            locality: "Reno",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
            serialNumber: "APCBPGN2202-AF250300028",
            ipAddress: "10.10.10.10",
            curve: "secp384r1",
            privateKeyAlias: privateKeyAlias  // REQUIRED for secure storage
        };

        const result = await CSRModule.generateCSR(params);

        console.log("✅ CSR Generated Securely!");
        console.log("CSR:", result.csr);
        console.log("Private Key Alias:", result.privateKeyAlias);
        console.log("Public Key:", result.publicKey);
        console.log("Hardware-Backed:", result.isHardwareBacked);

        // CRITICAL: Store the alias securely (e.g., encrypted shared preferences)
        // You'll need this alias later for signing operations or to retrieve the certificate
        await securelyStoreAlias(result.privateKeyAlias);

        // Send CSR to your CA server
        await sendCSRToCertificateAuthority(result.csr);

        return result;
    } catch (error) {
        console.error("Error generating secure CSR:", error);
        throw error;
    }
}

/**
 * Using device-specific alias
 */
async function generateCSRForDevice(deviceId: string, serialNumber: string) {
    try {
        // Use device-specific alias
        const privateKeyAlias = `device_${deviceId}_cert`;

        // Check if key already exists
        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (exists) {
            console.log("⚠️ Key already exists. Delete it first or use a different alias.");
            // Optionally delete the old key
            // await CSRModule.deleteKey(privateKeyAlias);
            throw new Error("Key already exists");
        }

        const params: CSRParams = {
            country: "US",
            state: "Nevada",
            locality: "Reno",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: deviceId,
            serialNumber: serialNumber,
            ipAddress: "10.10.10.10",
            curve: "secp384r1",
            privateKeyAlias: privateKeyAlias
        };

        const result = await CSRModule.generateCSR(params);

        console.log("✅ Secure CSR generated for device:", deviceId);
        console.log("Hardware-backed:", result.isHardwareBacked);

        return result;
    } catch (error) {
        console.error("Error generating CSR for device:", error);
        throw error;
    }
}

/**
 * Check if key exists before generating
 */
async function checkAndGenerateCSR(alias: string) {
    try {
        const exists = await CSRModule.keyExists(alias);

        if (exists) {
            console.log("✅ Key already exists. Retrieving public key...");
            const publicKey = await CSRModule.getPublicKey(alias);
            return { exists: true, publicKey };
        }

        console.log("Key doesn't exist. Generating new CSR...");
        const result = await CSRModule.generateCSR({
            commonName: "new-device",
            privateKeyAlias: alias
        });

        return { exists: false, result };
    } catch (error) {
        console.error("Error:", error);
        throw error;
    }
}

/**
 * Delete a key when device is decommissioned or certificate expires
 */
async function deleteDeviceKey(deviceId: string) {
    try {
        const privateKeyAlias = `device_${deviceId}_cert`;

        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (!exists) {
            console.log("Key doesn't exist");
            return false;
        }

        await CSRModule.deleteKey(privateKeyAlias);
        console.log("✅ Key deleted successfully");
        return true;
    } catch (error) {
        console.error("Error deleting key:", error);
        throw error;
    }
}

/**
 * Certificate renewal workflow
 */
async function renewCertificate(oldAlias: string) {
    try {
        // Generate new key pair with new alias
        const newAlias = `${oldAlias}_renewed_${Date.now()}`;

        const result = await CSRModule.generateCSR({
            country: "US",
            state: "Nevada",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
            serialNumber: "APCBPGN2202-AF250300028",
            ipAddress: "10.10.10.10",
            privateKeyAlias: newAlias
        });

        console.log("✅ New CSR generated for renewal");

        // Send CSR to CA, get new certificate
        await sendCSRToCertificateAuthority(result.csr);

        // After successful certificate installation, delete old key
        await CSRModule.deleteKey(oldAlias);
        console.log("✅ Old key deleted");

        return result;
    } catch (error) {
        console.error("Error renewing certificate:", error);
        throw error;
    }
}

/**
 * Retrieve public key for an existing key pair
 */
async function getExistingPublicKey(deviceId: string) {
    try {
        const privateKeyAlias = `device_${deviceId}_cert`;

        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (!exists) {
            throw new Error("Key not found");
        }

        const publicKey = await CSRModule.getPublicKey(privateKeyAlias);
        console.log("✅ Public key retrieved");
        return publicKey;
    } catch (error) {
        console.error("Error retrieving public key:", error);
        throw error;
    }
}

/**
 * Complete device provisioning workflow
 */
async function provisionDevice(deviceInfo: {
    deviceId: string;
    serialNumber: string;
    ipAddress: string;
}) {
    try {
        console.log("🔧 Starting device provisioning...");

        // Step 1: Generate unique alias
        const privateKeyAlias = `pwrview_${deviceInfo.deviceId}`;

        // Step 2: Check if already provisioned
        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (exists) {
            throw new Error("Device already provisioned. Delete existing key first.");
        }

        // Step 3: Generate CSR with hardware-backed key
        console.log("📝 Generating CSR...");
        const result = await CSRModule.generateCSR({
            country: "US",
            state: "Nevada",
            locality: "Reno",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: deviceInfo.deviceId,
            serialNumber: deviceInfo.serialNumber,
            ipAddress: deviceInfo.ipAddress,
            curve: "secp384r1",
            privateKeyAlias: privateKeyAlias
        });

        console.log("✅ CSR generated");
        console.log("🔐 Hardware-backed:", result.isHardwareBacked);

        // Step 4: Store alias securely
        await securelyStoreAlias(result.privateKeyAlias);

        // Step 5: Send CSR to CA
        console.log("📤 Sending CSR to Certificate Authority...");
        const certificate = await sendCSRToCertificateAuthority(result.csr);

        // Step 6: Store certificate
        await storeCertificate(certificate);

        console.log("✅ Device provisioned successfully!");

        return {
            privateKeyAlias: result.privateKeyAlias,
            isHardwareBacked: result.isHardwareBacked,
            certificate: certificate
        };
    } catch (error) {
        console.error("❌ Device provisioning failed:", error);
        throw error;
    }
}

/**
 * List all stored key aliases (you'll need to implement storage)
 */
async function listStoredKeyAliases() {
    // You would implement this using your secure storage mechanism
    // e.g., encrypted shared preferences or secure storage library
    const aliases = await getStoredAliases();

    for (const alias of aliases) {
        const exists = await CSRModule.keyExists(alias);
        console.log(`${alias}: ${exists ? '✅ exists' : '❌ missing'}`);
    }

    return aliases;
}

// Helper functions (implement based on your app architecture)

async function securelyStoreAlias(alias: string) {
    // Implement using encrypted shared preferences or secure storage
    // Example: await EncryptedStorage.setItem('privateKeyAlias', alias);
    console.log("Storing alias securely:", alias);
}

async function sendCSRToCertificateAuthority(csr: string) {
    // Implement your CA API call
    console.log("Sending CSR to CA...");
    // const response = await fetch('https://your-ca.example.com/api/csr', {
    //   method: 'POST',
    //   body: JSON.stringify({ csr })
    // });
    // return response.certificate;
}

async function storeCertificate(certificate: string) {
    // Store the certificate for later use
    console.log("Storing certificate...");
}

async function getStoredAliases(): Promise<string[]> {
    // Retrieve list of aliases from your secure storage
    return [];
}

export {
    generateSecureCSR,
    generateCSRForDevice,
    checkAndGenerateCSR,
    deleteDeviceKey,
    renewCertificate,
    getExistingPublicKey,
    provisionDevice,
    listStoredKeyAliases
};