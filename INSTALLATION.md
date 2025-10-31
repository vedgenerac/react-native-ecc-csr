# Installation Guide

## Prerequisites

- React Native >= 0.60.0
- iOS >= 11.0
- Android API Level >= 23 (Android 6.0)

## Installation Steps

### 1. Install the Package

```bash
npm install react-native-ecc-csr
# or
yarn add react-native-ecc-csr
```

### 2. iOS Setup

```bash
cd ios
pod install
cd ..
```

If you encounter any issues:

```bash
cd ios
pod deintegrate
pod install
cd ..
```

### 3. Android Setup

The package uses auto-linking for React Native >= 0.60, so no additional setup is required.

#### Android ProGuard (Optional)

If you use ProGuard, add these rules to `android/app/proguard-rules.pro`:

```proguard
# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
```

#### Android Build Configuration

If you have conflicts with BouncyCastle, add to `android/app/build.gradle`:

```gradle
android {
    packagingOptions {
        pickFirst 'META-INF/BCKEY.DSA'
        pickFirst 'META-INF/BCKEY.SF'
    }
}
```

### 4. Link (React Native < 0.60 only)

For older versions of React Native:

```bash
react-native link react-native-ecc-csr
```

### 5. Rebuild Your App

```bash
# iOS
npx react-native run-ios

# Android
npx react-native run-android
```

## Verifying Installation

Create a test file to verify the installation:

```javascript
import { generateCSR } from 'react-native-ecc-csr';

async function test() {
  try {
    const result = await generateCSR({
      commonName: 'test-device',
      curve: 'P-256',
    });
    console.log('Installation successful!');
    console.log('CSR:', result.csr);
  } catch (error) {
    console.error('Installation failed:', error);
  }
}

test();
```

## Troubleshooting

### iOS Build Errors

**Error: "Module not found"**

```bash
cd ios
pod install
cd ..
npx react-native run-ios
```

**Error: "Undefined symbols"**

1. Open Xcode
2. Clean Build Folder (Cmd + Shift + K)
3. Rebuild (Cmd + B)

### Android Build Errors

**Error: "Duplicate class"**

This usually means BouncyCastle is included twice. Add to `android/app/build.gradle`:

```gradle
configurations.all {
    exclude group: 'org.bouncycastle', module: 'bcprov-jdk15on'
}
```

**Error: "AndroidKeyStore not found"**

Make sure your `minSdkVersion` is at least 23:

```gradle
android {
    defaultConfig {
        minSdkVersion 23
    }
}
```

### Runtime Errors

**Error: "EccCsrGenerator native module is not available"**

1. Make sure you've rebuilt the app after installation
2. For iOS: `cd ios && pod install && cd ..`
3. Clear caches: `npx react-native start --reset-cache`
4. Rebuild: `npx react-native run-ios` or `npx react-native run-android`

**Error: "Key generation failed"**

- On Android: Make sure the device/emulator supports hardware-backed keystore
- On iOS: Make sure the app has proper permissions

## Platform-Specific Notes

### iOS

- Keys are stored in iOS Keychain
- Hardware-backed keys when available (Secure Enclave)
- No additional permissions required

### Android

- Keys are stored in Android KeyStore
- Hardware-backed keys on supported devices
- Requires Android API 23+ for full functionality

## Next Steps

After successful installation:

1. Read the [README.md](README.md) for API documentation
2. Check out the [example/App.js](example/App.js) for usage examples
3. Review security considerations in the README

## Support

If you encounter any issues:

1. Check the troubleshooting section above
2. Search existing GitHub issues
3. Create a new issue with:
   - React Native version
   - iOS/Android version
   - Full error message
   - Steps to reproduce