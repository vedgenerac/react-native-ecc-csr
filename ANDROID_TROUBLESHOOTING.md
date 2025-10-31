# Android Build Troubleshooting

## Common Android Build Issues

### Issue 1: BouncyCastle Jetifier Error

**Error:**
```
Failed to transform bcprov-jdk18on-1.78.jar
IllegalArgumentException, message: Unsupported class file major version 65
```

**Solution 1 - Disable Jetifier for BouncyCastle (Recommended)**

Add this to your app's `android/gradle.properties`:

```properties
# Disable Jetifier (React Native 0.71+)
android.enableJetifier=false
```

Or if you need Jetifier for other libraries, exclude BouncyCastle:

Create/edit `android/jetifier.config.json`:

```json
{
  "ignoredLibraries": [
    "bcprov-jdk15on",
    "bcpkix-jdk15on"
  ]
}
```

**Solution 2 - Update Your Gradle Version**

If using older React Native, update your Android Gradle plugin in `android/build.gradle`:

```gradle
buildscript {
    dependencies {
        classpath("com.android.tools.build:gradle:7.4.2")
    }
}
```

**Solution 3 - Force BouncyCastle Version in Your App**

Add to your app's `android/app/build.gradle`:

```gradle
dependencies {
    // Force use of compatible BouncyCastle version
    implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
    implementation 'org.bouncycastle:bcpkix-jdk15on:1.70'
}
```

### Issue 2: Duplicate BouncyCastle Classes

**Error:**
```
Duplicate class org.bouncycastle.*
```

**Solution:**

Add to your app's `android/app/build.gradle`:

```gradle
android {
    packagingOptions {
        pickFirst 'META-INF/BCKEY.DSA'
        pickFirst 'META-INF/BCKEY.SF'
        exclude 'META-INF/versions/9/OSGI-INF/MANIFEST.MF'
    }
}

configurations.all {
    resolutionStrategy {
        force 'org.bouncycastle:bcprov-jdk15on:1.70'
        force 'org.bouncycastle:bcpkix-jdk15on:1.70'
    }
}
```

### Issue 3: Module not found error

**Error:**
```
Native module cannot be null
```

**Solution:**

1. Clean and rebuild:
```bash
cd android
./gradlew clean
cd ..
npx react-native run-android
```

2. Check that the package is linked (should be automatic for RN 0.60+)

3. Verify in `android/settings.gradle`:
```gradle
include ':react-native-ecc-csr'
project(':react-native-ecc-csr').projectDir = new File(rootProject.projectDir, '../node_modules/react-native-ecc-csr/android')
```

4. Verify in `android/app/build.gradle`:
```gradle
dependencies {
    implementation project(':react-native-ecc-csr')
}
```

### Issue 4: Java Version Mismatch

**Error:**
```
Unsupported class file major version
```

**Solution:**

Update `android/gradle.properties`:

```properties
org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=512m
```

And in `android/build.gradle`:

```gradle
allprojects {
    repositories {
        // ...
    }
    
    gradle.projectsEvaluated {
        tasks.withType(JavaCompile) {
            options.compilerArgs << "-Xlint:unchecked" << "-Xlint:deprecation"
            sourceCompatibility = JavaVersion.VERSION_11
            targetCompatibility = JavaVersion.VERSION_11
        }
    }
}
```

### Issue 5: Minimum SDK Version

**Error:**
```
Manifest merger failed : uses-sdk:minSdkVersion 21 cannot be smaller than version 23
```

**Solution:**

Update your app's `android/app/build.gradle`:

```gradle
android {
    defaultConfig {
        minSdkVersion 23  // Required for this package
        targetSdkVersion 33
    }
}
```

## Complete Setup for New Projects

### Step 1: Install Package

```bash
npm install react-native-ecc-csr
# or
yarn add react-native-ecc-csr
```

### Step 2: Update android/gradle.properties

```properties
# Gradle properties
org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=512m
android.useAndroidX=true

# Disable Jetifier if you don't need it
android.enableJetifier=false
```

### Step 3: Update android/build.gradle

```gradle
buildscript {
    ext {
        buildToolsVersion = "33.0.0"
        minSdkVersion = 23
        compileSdkVersion = 33
        targetSdkVersion = 33
    }
    dependencies {
        classpath("com.android.tools.build:gradle:7.4.2")
    }
}
```

### Step 4: Update android/app/build.gradle

```gradle
android {
    defaultConfig {
        minSdkVersion rootProject.ext.minSdkVersion
        targetSdkVersion rootProject.ext.targetSdkVersion
    }

    packagingOptions {
        pickFirst 'META-INF/BCKEY.DSA'
        pickFirst 'META-INF/BCKEY.SF'
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_11
        targetCompatibility JavaVersion.VERSION_11
    }
}

dependencies {
    // ... other dependencies
    
    // Force BouncyCastle version if needed
    implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
    implementation 'org.bouncycastle:bcpkix-jdk15on:1.70'
}
```

### Step 5: Clean and Rebuild

```bash
cd android
./gradlew clean
cd ..
npx react-native run-android
```

## React Native Version Compatibility

| React Native Version | Gradle Plugin | Java Version | Notes |
|---------------------|---------------|--------------|-------|
| 0.73+ | 8.0+ | 17 | Latest, recommended |
| 0.71-0.72 | 7.4+ | 11 | Stable |
| 0.68-0.70 | 7.0+ | 11 | Use Jetifier |
| 0.60-0.67 | 4.2+ | 8/11 | Use Jetifier |

## Testing Your Build

```bash
# Clean everything
cd android
./gradlew clean
rm -rf .gradle
rm -rf build
rm -rf app/build
cd ..

# Clear React Native cache
npx react-native start --reset-cache

# In another terminal, rebuild
npx react-native run-android
```

## Verification

After successful build, test the module:

```javascript
import { generateCSR } from 'react-native-ecc-csr';

async function testModule() {
  try {
    const result = await generateCSR({
      commonName: 'test',
      curve: 'P-256'
    });
    console.log('✅ Module working!');
    console.log(result.csr);
  } catch (error) {
    console.error('❌ Module error:', error);
  }
}

testModule();
```

## Still Having Issues?

1. Check your React Native version: `npx react-native --version`
2. Check your Gradle version: `cd android && ./gradlew --version`
3. Check Java version: `java -version`
4. Try using a different BouncyCastle version (1.68-1.70 range)
5. Create an issue on GitHub with:
   - React Native version
   - Android version (emulator/device)
   - Full error log with `--stacktrace`

## Quick Fix Commands

```bash
# Nuclear option - complete clean
cd android
./gradlew clean
rm -rf ~/.gradle/caches/
cd ..
rm -rf node_modules
npm install
cd android
./gradlew clean
cd ..
npx react-native run-android
```

## ProGuard Configuration (if using)

Add to `android/app/proguard-rules.pro`:

```proguard
# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# React Native ECC CSR
-keep class com.ecccsrgen.** { *; }
```

## Support

If none of these solutions work, please provide:
1. React Native version
2. Android Gradle Plugin version
3. Java version
4. Full error log with `./gradlew app:installDebug --stacktrace`