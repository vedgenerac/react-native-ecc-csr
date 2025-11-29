import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-ecc-csr' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const EccCsrGenerator = NativeModules.EccCsrGenerator
  ? NativeModules.EccCsrGenerator
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export interface CSRParams {
  commonName: string;
  serialNumber?: string;
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationalUnit?: string;
  ipAddress?: string;
  phoneDeviceId?: string; // ✅ NEW: Device ID + Make/Model (format: "deviceId|makeModel")
  curve?: 'secp256r1' | 'secp384r1' | 'secp521r1' | 'P-256' | 'P-384' | 'P-521';
  privateKeyAlias?: string; // Required for Android
}

export interface CSRResult {
  csr: string;
  publicKey: string;
  privateKeyAlias?: string; // Android only
  isHardwareBacked?: boolean; // Android only
}

/**
 * Generate an ECC Certificate Signing Request (CSR)
 * 
 * @param params - CSR generation parameters
 * @returns Promise resolving to CSR and public key
 * 
 * @example
 * ```typescript
 * import { generateCSR } from 'react-native-ecc-csr';
 * import DeviceInfo from 'react-native-device-info';
 * 
 * const deviceId = await DeviceInfo.getUniqueId();
 * const brand = DeviceInfo.getBrand();
 * const model = DeviceInfo.getModel();
 * 
 * const result = await generateCSR({
 *   commonName: 'device-001',
 *   serialNumber: 'SERIAL-12345',
 *   country: 'US',
 *   state: 'Nevada',
 *   locality: 'Reno',
 *   organization: 'Generac',
 *   organizationalUnit: 'PWRview',
 *   ipAddress: '10.10.10.10',
 *   phoneDeviceId: `${deviceId}|${brand}_${model}`,
 *   curve: 'secp384r1',
 *   privateKeyAlias: 'my-key-alias' // Required for Android
 * });
 * 
 * console.log('CSR:', result.csr);
 * console.log('Public Key:', result.publicKey);
 * ```
 */
export function generateCSR(params: CSRParams): Promise<CSRResult> {
  return EccCsrGenerator.generateCSR(params);
}

// Android-specific methods (no-op on iOS)
export function deleteKey(privateKeyAlias: string): Promise<boolean> {
  if (Platform.OS === 'android' && EccCsrGenerator.deleteKey) {
    return EccCsrGenerator.deleteKey(privateKeyAlias);
  }
  return Promise.resolve(false);
}

export function keyExists(privateKeyAlias: string): Promise<boolean> {
  if (Platform.OS === 'android' && EccCsrGenerator.keyExists) {
    return EccCsrGenerator.keyExists(privateKeyAlias);
  }
  return Promise.resolve(false);
}

export function getPublicKey(privateKeyAlias: string): Promise<string> {
  if (Platform.OS === 'android' && EccCsrGenerator.getPublicKey) {
    return EccCsrGenerator.getPublicKey(privateKeyAlias);
  }
  return Promise.reject(new Error('getPublicKey is only available on Android'));
}

export default {
  generateCSR,
  deleteKey,
  keyExists,
  getPublicKey,
};
