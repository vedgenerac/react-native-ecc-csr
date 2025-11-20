import { NativeModules } from 'react-native';

const { CSRModule } = NativeModules;

export type ECCurve = 'secp256r1' | 'secp384r1' | 'secp521r1';

export interface CSRParams {
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationalUnit?: string;
  commonName: string;
  serialNumber?: string;
  ipAddress?: string;
  curve?: ECCurve; // P-256, P-384 (default), or P-521
}

export interface CSRResult {
  csr: string;
  privateKey: string;
  publicKey: string;
}

export interface KeyPairParams {
  curve?: ECCurve; // P-256, P-384 (default), or P-521
}

export interface KeyPairResult {
  privateKey: string;
  publicKey: string;
}

export interface CSRModuleInterface {
  /**
   * Generates a Certificate Signing Request (CSR) with ECC key pair
   * @param params - CSR parameters including subject DN, SAN IP address, and curve
   * @returns Promise resolving to CSR, private key, and public key in PEM format
   */
  generateCSR(params: CSRParams): Promise<CSRResult>;

  /**
   * Generates an ECC key pair
   * @param params - Key pair parameters including curve selection
   * @returns Promise resolving to private and public keys
   */
  generateKeyPair(params: KeyPairParams): Promise<KeyPairResult>;
}

export default CSRModule as CSRModuleInterface;