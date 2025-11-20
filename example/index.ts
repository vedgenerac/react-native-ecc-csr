import CSRModule, { CSRParams } from 'react-native-ecc-csr';

/**
 * Example 1: Generate CSR with all parameters (using default P-384 curve)
 */
async function generateCSRExample() {
    try {
        const params: CSRParams = {
            country: "US",
            state: "Nevada",
            locality: "Reno",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
            serialNumber: "APCBPGN2202-AF250300028",
            ipAddress: "10.10.10.10",
            curve: "secp384r1" // P-384 (default if not specified)
        };

        const result = await CSRModule.generateCSR(params);

        console.log("CSR Generated:");
        console.log("==============");
        console.log("CSR:\n", result.csr);
        console.log("\nPrivate Key:\n", result.privateKey);
        console.log("\nPublic Key:\n", result.publicKey);

        // Save to file or send to server
        // await saveToFile('csr.pem', result.csr);
        // await saveToFile('private_key.pem', result.privateKey);

        return result;
    } catch (error) {
        console.error("Error generating CSR:", error);
        throw error;
    }
}

/**
 * Example 2: Generate CSR with minimal parameters (using defaults)
 */
async function generateMinimalCSR() {
    try {
        const params: CSRParams = {
            commonName: "device-12345",
            serialNumber: "SN-67890"
        };

        const result = await CSRModule.generateCSR(params);
        return result;
    } catch (error) {
        console.error("Error generating minimal CSR:", error);
        throw error;
    }
}

/**
 * Example 3: Generate just a key pair (default P-384)
 */
async function generateKeyPairExample() {
    try {
        const keyPair = await CSRModule.generateKeyPair({ curve: "secp384r1" });

        console.log("Key Pair Generated:");
        console.log("==================");
        console.log("Private Key:\n", keyPair.privateKey);
        console.log("\nPublic Key:\n", keyPair.publicKey);

        return keyPair;
    } catch (error) {
        console.error("Error generating key pair:", error);
        throw error;
    }
}

/**
 * Example 4: Generate CSR with custom IP address
 */
async function generateCSRWithCustomIP() {
    try {
        const params: CSRParams = {
            country: "US",
            state: "California",
            locality: "San Francisco",
            organization: "My Company",
            organizationalUnit: "IT",
            commonName: "api.mycompany.com",
            serialNumber: "DEVICE-001",
            ipAddress: "192.168.1.100"  // Custom IP
        };

        const result = await CSRModule.generateCSR(params);
        return result;
    } catch (error) {
        console.error("Error generating CSR with custom IP:", error);
        throw error;
    }
}

/**
 * Example 5: Generate CSR with P-256 curve (smaller, faster)
 */
async function generateCSRWithP256() {
    try {
        const params: CSRParams = {
            country: "US",
            state: "Texas",
            locality: "Austin",
            organization: "Tech Corp",
            organizationalUnit: "Security",
            commonName: "device-p256",
            serialNumber: "P256-001",
            ipAddress: "10.0.0.1",
            curve: "secp256r1"  // P-256 curve
        };

        const result = await CSRModule.generateCSR(params);
        console.log("CSR with P-256 curve generated");
        return result;
    } catch (error) {
        console.error("Error generating CSR with P-256:", error);
        throw error;
    }
}

/**
 * Example 6: Generate CSR with P-521 curve (maximum security)
 */
async function generateCSRWithP521() {
    try {
        const params: CSRParams = {
            country: "US",
            state: "New York",
            locality: "New York",
            organization: "High Security Corp",
            organizationalUnit: "Cryptography",
            commonName: "device-p521",
            serialNumber: "P521-001",
            ipAddress: "10.0.0.2",
            curve: "secp521r1"  // P-521 curve (highest security)
        };

        const result = await CSRModule.generateCSR(params);
        console.log("CSR with P-521 curve generated");
        return result;
    } catch (error) {
        console.error("Error generating CSR with P-521:", error);
        throw error;
    }
}

/**
 * Example 7: Generate key pair with P-256
 */
async function generateP256KeyPair() {
    try {
        const keyPair = await CSRModule.generateKeyPair({ curve: "secp256r1" });
        console.log("P-256 key pair generated");
        return keyPair;
    } catch (error) {
        console.error("Error generating P-256 key pair:", error);
        throw error;
    }
}

/**
 * Example 8: Generate key pair with P-521
 */
async function generateP521KeyPair() {
    try {
        const keyPair = await CSRModule.generateKeyPair({ curve: "secp521r1" });
        console.log("P-521 key pair generated");
        return keyPair;
    } catch (error) {
        console.error("Error generating P-521 key pair:", error);
        throw error;
    }
}

// Usage in a React Native component
export function CSRComponent() {
    const handleGenerateCSR = async () => {
        try {
            const result = await generateCSRExample();
            // Do something with the result
            console.log("CSR generation successful!");
        } catch (error) {
            console.error("Failed to generate CSR:", error);
        }
    };

    return (
        // Your UI component here
        null
    );
}

export {
    generateCSRExample,
    generateMinimalCSR,
    generateKeyPairExample,
    generateCSRWithCustomIP,
    generateCSRWithP256,
    generateCSRWithP521,
    generateP256KeyPair,
    generateP521KeyPair
};