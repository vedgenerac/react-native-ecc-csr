import { NativeModules, Platform } from 'react-native';

const { EccCsrGenerator } = NativeModules;

if (!EccCsrGenerator) {
    throw new Error(
        'EccCsrGenerator native module is not available. ' +
        'Make sure you have linked the library and rebuilt your app.'
    );
}

/**
 * ECC Curve options
 */
export const ECCCurve = {
    P256: 'P-256',
    P384: 'P-384',
    P521: 'P-521',
};

/**
 * Generate a Certificate Signing Request (CSR) using ECC
 * 
 * @param {Object} options - CSR generation options
 * @param {string} options.commonName - Common Name (CN) - Required
 * @param {string} [options.serialNumber] - Serial Number (will be appended to CN)
 * @param {string} [options.country] - Country (C)
 * @param {string} [options.state] - State/Province (ST)
 * @param {string} [options.locality] - Locality/City (L)
 * @param {string} [options.organization] - Organization (O)
 * @param {string} [options.organizationalUnit] - Organizational Unit (OU)
 * @param {string} [options.ipAddress] - IP Address for Subject Alternative Name
 * @param {string} [options.curve] - ECC curve: 'P-256', 'P-384', or 'P-521' (default: 'P-384')
 * @param {string} [options.keyAlias] - Key alias for storage (default: 'ECC_CSR_KEY')
 * 
 * @returns {Promise<{csr: string, publicKey: string}>} CSR in PEM format and public key
 * 
 * @example
 * const result = await generateCSR({
 *   commonName: '5dab25dd-7d0a-4a03-94c3-39f935c0a48a',
 *   serialNumber: 'APCBPGN2202-AF250300028',
 *   country: 'US',
 *   state: 'Nevada',
 *   locality: 'Reno',
 *   organization: 'Generac',
 *   organizationalUnit: 'PWRview',
 *   ipAddress: '10.10.10.10',
 *   curve: 'P-384'
 * });
 * console.log(result.csr);
 */
export async function generateCSR(options) {
    if (!options || !options.commonName) {
        throw new Error('commonName is required');
    }

    // Validate curve
    const validCurves = ['P-256', 'P-384', 'P-521'];
    const curve = options.curve || 'P-384';
    if (!validCurves.includes(curve)) {
        throw new Error(`Invalid curve. Must be one of: ${validCurves.join(', ')}`);
    }

    const params = {
        commonName: options.commonName,
        serialNumber: options.serialNumber || '',
        country: options.country || '',
        state: options.state || '',
        locality: options.locality || '',
        organization: options.organization || '',
        organizationalUnit: options.organizationalUnit || '',
        ipAddress: options.ipAddress || '',
        curve: curve,
        keyAlias: options.keyAlias || 'ECC_CSR_KEY',
    };

    try {
        const result = await EccCsrGenerator.generateCSR(params);
        return result;
    } catch (error) {
        throw new Error(`Failed to generate CSR: ${error.message}`);
    }
}

/**
 * Get the public key for an existing key pair
 * 
 * @param {string} [keyAlias] - Key alias (default: 'ECC_CSR_KEY')
 * @returns {Promise<string>} Public key in PEM format
 */
export async function getPublicKey(keyAlias = 'ECC_CSR_KEY') {
    try {
        const publicKey = await EccCsrGenerator.getPublicKey(keyAlias);
        return publicKey;
    } catch (error) {
        throw new Error(`Failed to get public key: ${error.message}`);
    }
}

/**
 * Delete the key pair from storage
 * 
 * @param {string} [keyAlias] - Key alias (default: 'ECC_CSR_KEY')
 * @returns {Promise<boolean>} Success status
 */
export async function deleteKeyPair(keyAlias = 'ECC_CSR_KEY') {
    try {
        const result = await EccCsrGenerator.deleteKeyPair(keyAlias);
        return result;
    } catch (error) {
        throw new Error(`Failed to delete key pair: ${error.message}`);
    }
}

/**
 * Check if a key pair exists
 * 
 * @param {string} [keyAlias] - Key alias (default: 'ECC_CSR_KEY')
 * @returns {Promise<boolean>} True if key pair exists
 */
export async function hasKeyPair(keyAlias = 'ECC_CSR_KEY') {
    try {
        const result = await EccCsrGenerator.hasKeyPair(keyAlias);
        return result;
    } catch (error) {
        return false;
    }
}

export default {
    generateCSR,
    getPublicKey,
    deleteKeyPair,
    hasKeyPair,
    ECCCurve,
};