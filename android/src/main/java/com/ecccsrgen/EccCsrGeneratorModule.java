package com.ecccsrgen;

import android.content.Context;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Collection;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private final ReactApplicationContext reactContext;
    private MqttClient client;

    public MqttModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
        
        // Add BouncyCastle as security provider if not already added
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            Log.d(TAG, "BouncyCastle provider added at position 1");
        } else {
            Log.d(TAG, "BouncyCastle provider already present");
        }
        
        Log.i(TAG, "=== MqttModule Initialized ===");
        Log.d(TAG, "Security providers available:");
        for (java.security.Provider provider : Security.getProviders()) {
            Log.d(TAG, "  - " + provider.getName() + " v" + provider.getVersion());
        }
    }

    @Override
    public String getName() {
        return "MqttModule";
    }

    private String sanitizePEM(String pem, String type) {
        if (pem == null) return null;
        
        Log.d(TAG, "=== Sanitizing " + type + " ===");
        Log.d(TAG, "Original length: " + pem.length());
        Log.d(TAG, "Original starts with: " + pem.substring(0, Math.min(60, pem.length())));
        
        // Normalize line endings
        String sanitized = pem.replaceAll("\\r\\n", "\n").replaceAll("\\r", "\n");
        
        // Fix common PEM header/footer issues
        // Replace incorrect dash counts (4 or 6 dashes) with correct 5 dashes
        sanitized = sanitized.replaceAll("-{4,6}BEGIN", "-----BEGIN");
        sanitized = sanitized.replaceAll("BEGIN([^-]*)-{4,6}", "BEGIN$1-----");
        sanitized = sanitized.replaceAll("-{4,6}END", "-----END");
        sanitized = sanitized.replaceAll("END([^-]*)-{4,6}", "END$1-----");
        
        // Remove any leading/trailing whitespace
        sanitized = sanitized.trim();
        
        // Ensure proper spacing around headers and footers
        sanitized = sanitized.replaceAll("(-----BEGIN [^-]+-----)", "$1\n");
        sanitized = sanitized.replaceAll("(-----END [^-]+-----)", "\n$1");
        
        // Remove any double newlines that might have been created
        sanitized = sanitized.replaceAll("\n\n+", "\n");
        
        // Ensure it ends with a newline
        if (!sanitized.endsWith("\n")) {
            sanitized += "\n";
        }
        
        Log.d(TAG, "Sanitized length: " + sanitized.length());
        Log.d(TAG, "Sanitized starts with: " + sanitized.substring(0, Math.min(60, sanitized.length())));
        
        // Count how many certificates/keys are in the PEM
        int beginCount = sanitized.split("-----BEGIN").length - 1;
        int endCount = sanitized.split("-----END").length - 1;
        Log.d(TAG, "Number of BEGIN markers: " + beginCount);
        Log.d(TAG, "Number of END markers: " + endCount);
        
        if (beginCount != endCount) {
            Log.w(TAG, "⚠️ WARNING: BEGIN and END marker count mismatch!");
        }
        
        Log.i(TAG, type + " sanitization complete");
        
        return sanitized;
    }

    @ReactMethod
    public void connect(String broker, String clientId, ReadableMap certificates, Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ MQTT Connection Request");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Broker: " + broker);
            Log.d(TAG, "║ Client ID: " + clientId);
            Log.d(TAG, "║ Timestamp: " + new java.util.Date().toString());
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            // Extract and sanitize certificate contents from ReadableMap
            String clientCertPem = certificates.hasKey("clientCert") ? sanitizePEM(certificates.getString("clientCert"), "Client Cert") : null;
            String clientKeyPem = certificates.hasKey("clientKey") ? sanitizePEM(certificates.getString("clientKey"), "Client Key") : null;
            String rootCaPem = certificates.hasKey("rootCa") ? sanitizePEM(certificates.getString("rootCa"), "Root CA") : null;

            // Validate that all required certificates are provided
            if (clientCertPem == null || clientKeyPem == null || rootCaPem == null) {
                String error = "Missing certificate content. Please provide clientCert, clientKey, and rootCa.";
                Log.e(TAG, "❌ " + error);
                Log.e(TAG, "  clientCert provided: " + (clientCertPem != null));
                Log.e(TAG, "  clientKey provided: " + (clientKeyPem != null));
                Log.e(TAG, "  rootCa provided: " + (rootCaPem != null));
                errorCallback.invoke(error);
                return;
            }

            Log.i(TAG, "✓ All certificates provided and sanitized");
            Log.d(TAG, "  Client cert length: " + clientCertPem.length() + " bytes");
            Log.d(TAG, "  Client key length: " + clientKeyPem.length() + " bytes");
            Log.d(TAG, "  Root CA length: " + rootCaPem.length() + " bytes");

            // Initialize MQTT client
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Creating MQTT Client");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            client = new MqttClient(broker, clientId, new MemoryPersistence());
            Log.i(TAG, "✓ MQTT client created successfully");

            // Configure connection options
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 2: Configuring Connection Options");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            options.setConnectionTimeout(60);
            options.setKeepAliveInterval(60);
            options.setAutomaticReconnect(false);
            
            Log.d(TAG, "  Clean session: " + options.isCleanSession());
            Log.d(TAG, "  Connection timeout: " + options.getConnectionTimeout() + "s");
            Log.d(TAG, "  Keep alive interval: " + options.getKeepAliveInterval() + "s");
            Log.d(TAG, "  Automatic reconnect: " + options.isAutomaticReconnect());
            Log.d(TAG, "  MQTT version: " + options.getMqttVersion());

            // Configure mTLS
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Creating SSL Context");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            SSLContext sslContext = createSslContext(clientCertPem, clientKeyPem, rootCaPem);
            Log.i(TAG, "✓ SSL context created successfully");
            
            options.setSocketFactory(sslContext.getSocketFactory());
            Log.d(TAG, "✓ Socket factory set on connection options");
            
            // CRITICAL: Disable hostname verification to allow IP address connections
            options.setHttpsHostnameVerificationEnabled(false);
            Log.d(TAG, "✓ Hostname verification disabled (for IP-based connection)");

            // Set callback for MQTT events
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 4: Setting MQTT Callbacks");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.d(TAG, "");
                    Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ ✓✓✓ MQTT CONNECTION SUCCESSFUL ✓✓✓");
                    Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ Server URI: " + serverURI);
                    Log.i(TAG, "║ Reconnect: " + reconnect);
                    Log.i(TAG, "║ Timestamp: " + new java.util.Date().toString());
                    Log.i(TAG, "╚════════════════════════════════════════════════════════════════");
                    sendEvent("MqttConnect", "Connected");
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.e(TAG, "");
                    Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ ❌ MQTT CONNECTION LOST");
                    Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());
                    if (cause != null) {
                        Log.e(TAG, "║ Cause: " + cause.getMessage());
                        Log.e(TAG, "║ Cause type: " + cause.getClass().getName());
                        Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
                        cause.printStackTrace();
                    } else {
                        Log.e(TAG, "║ Cause: Unknown");
                        Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
                    }
                    sendEvent("MqttConnectionLost", cause != null ? cause.getMessage() : "Unknown error");
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) {
                    String payload = new String(message.getPayload());
                    Log.d(TAG, "");
                    Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
                    Log.d(TAG, "│ 📨 MQTT Message Received");
                    Log.d(TAG, "├─────────────────────────────────────────────────────────────");
                    Log.d(TAG, "│ Topic: " + topic);
                    Log.d(TAG, "│ Payload: " + payload);
                    Log.d(TAG, "│ QoS: " + message.getQos());
                    Log.d(TAG, "│ Retained: " + message.isRetained());
                    Log.d(TAG, "│ Duplicate: " + message.isDuplicate());
                    Log.d(TAG, "│ Timestamp: " + new java.util.Date().toString());
                    Log.d(TAG, "└─────────────────────────────────────────────────────────────");
                    sendEvent("MqttMessage", topic + ":" + payload);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    Log.d(TAG, "");
                    Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
                    Log.d(TAG, "│ ✓ MQTT Message Delivered");
                    Log.d(TAG, "├─────────────────────────────────────────────────────────────");
                    try {
                        Log.d(TAG, "│ Message ID: " + token.getMessageId());
                        Log.d(TAG, "│ Topics: " + java.util.Arrays.toString(token.getTopics()));
                    } catch (Exception e) {
                        Log.w(TAG, "│ Could not get token details: " + e.getMessage());
                    }
                    Log.d(TAG, "│ Timestamp: " + new java.util.Date().toString());
                    Log.d(TAG, "└─────────────────────────────────────────────────────────────");
                }
            });
            Log.i(TAG, "✓ Callback handlers configured");

            // Connect to broker
            Log.d(TAG, "");
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Step 5: Initiating MQTT Connection");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Target: " + broker);
            Log.d(TAG, "║ Client ID: " + clientId);
            Log.d(TAG, "║ Protocol: MQTT over TLS (mqtts)");
            Log.d(TAG, "║ Status: Connecting...");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
            
            long startTime = System.currentTimeMillis();
            client.connect(options);
            long endTime = System.currentTimeMillis();
            
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ Connection command sent successfully in " + (endTime - startTime) + "ms");
            successCallback.invoke("Connected to " + broker);
            
        } catch (MqttException e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ MQTT EXCEPTION OCCURRED");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Exception Type: MqttException");
            Log.e(TAG, "║ Message: " + e.getMessage());
            Log.e(TAG, "║ Reason Code: " + e.getReasonCode());
            Log.e(TAG, "║ Reason: " + getMqttReasonCodeDescription(e.getReasonCode()));
            Log.e(TAG, "║ Localized Message: " + e.getLocalizedMessage());
            Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());
            
            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
                Log.e(TAG, "║ Cause Type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
            
            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();
            
            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }
            
            String errorMessage = "MQTT Error [Code: " + e.getReasonCode() + " - " + getMqttReasonCodeDescription(e.getReasonCode()) + "] " + e.getMessage();
            if (e.getCause() != null) {
                errorMessage += " | Root Cause: " + e.getCause().getMessage();
            }
            errorCallback.invoke(errorMessage);
            
        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ GENERAL EXCEPTION OCCURRED");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Exception Type: " + e.getClass().getName());
            Log.e(TAG, "║ Message: " + e.getMessage());
            Log.e(TAG, "║ Localized Message: " + e.getLocalizedMessage());
            Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());
            
            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
                Log.e(TAG, "║ Cause Type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
            
            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();
            
            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }
            
            errorCallback.invoke("Connection error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    @ReactMethod
    public void subscribe(String topic, int qos) {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Subscribe Request");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Topic: " + topic);
            Log.d(TAG, "│ QoS: " + qos);
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            if (client != null && client.isConnected()) {
                client.subscribe(topic, qos);
                Log.i(TAG, "✓ Successfully subscribed to: " + topic);
            } else {
                Log.e(TAG, "❌ Cannot subscribe: Client not connected");
                Log.e(TAG, "  Client is null: " + (client == null));
                if (client != null) {
                    Log.e(TAG, "  Client connected: " + client.isConnected());
                }
            }
        } catch (MqttException e) {
            Log.e(TAG, "");
            Log.e(TAG, "❌ Subscribe Error");
            Log.e(TAG, "  Topic: " + topic);
            Log.e(TAG, "  Error message: " + e.getMessage());
            Log.e(TAG, "  Reason code: " + e.getReasonCode());
            Log.e(TAG, "  Reason: " + getMqttReasonCodeDescription(e.getReasonCode()));
            e.printStackTrace();
        }
    }

    @ReactMethod
    public void publish(String topic, String message, int qos, boolean retained) {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Publish Request");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Topic: " + topic);
            Log.d(TAG, "│ Message: " + message);
            Log.d(TAG, "│ QoS: " + qos);
            Log.d(TAG, "│ Retained: " + retained);
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            if (client != null && client.isConnected()) {
                MqttMessage mqttMessage = new MqttMessage(message.getBytes());
                mqttMessage.setQos(qos);
                mqttMessage.setRetained(retained);
                client.publish(topic, mqttMessage);
                Log.i(TAG, "✓ Message published successfully to: " + topic);
            } else {
                Log.e(TAG, "❌ Cannot publish: Client not connected");
                Log.e(TAG, "  Client is null: " + (client == null));
                if (client != null) {
                    Log.e(TAG, "  Client connected: " + client.isConnected());
                }
            }
        } catch (MqttException e) {
            Log.e(TAG, "");
            Log.e(TAG, "❌ Publish Error");
            Log.e(TAG, "  Topic: " + topic);
            Log.e(TAG, "  Error message: " + e.getMessage());
            Log.e(TAG, "  Reason code: " + e.getReasonCode());
            Log.e(TAG, "  Reason: " + getMqttReasonCodeDescription(e.getReasonCode()));
            e.printStackTrace();
        }
    }

    @ReactMethod
    public void disconnect(Callback callback) {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Disconnect Request");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            if (client != null && client.isConnected()) {
                client.disconnect();
                Log.i(TAG, "✓ Disconnected successfully");
                callback.invoke("Disconnected");
            } else {
                Log.w(TAG, "⚠️ Disconnect called but client not connected");
                Log.w(TAG, "  Client is null: " + (client == null));
                if (client != null) {
                    Log.w(TAG, "  Client connected: " + client.isConnected());
                }
                callback.invoke("Client was not connected");
            }
        } catch (MqttException e) {
            Log.e(TAG, "");
            Log.e(TAG, "❌ Disconnect Error");
            Log.e(TAG, "  Error message: " + e.getMessage());
            Log.e(TAG, "  Reason code: " + e.getReasonCode());
            Log.e(TAG, "  Reason: " + getMqttReasonCodeDescription(e.getReasonCode()));
            e.printStackTrace();
            callback.invoke("Disconnect error: " + e.getMessage());
        }
    }

    private String getMqttReasonCodeDescription(int reasonCode) {
        switch (reasonCode) {
            case MqttException.REASON_CODE_BROKER_UNAVAILABLE:
                return "Broker unavailable";
            case MqttException.REASON_CODE_CLIENT_TIMEOUT:
                return "Client timeout";
            case MqttException.REASON_CODE_CONNECTION_LOST:
                return "Connection lost";
            case MqttException.REASON_CODE_SERVER_CONNECT_ERROR:
                return "Server connect error";
            case MqttException.REASON_CODE_FAILED_AUTHENTICATION:
                return "Failed authentication";
            case MqttException.REASON_CODE_SOCKET_FACTORY_MISMATCH:
                return "Socket factory mismatch";
            case MqttException.REASON_CODE_SSL_CONFIG_ERROR:
                return "SSL configuration error";
            case MqttException.REASON_CODE_CLIENT_EXCEPTION:
                return "Client exception";
            case MqttException.REASON_CODE_INVALID_PROTOCOL_VERSION:
                return "Invalid protocol version";
            case MqttException.REASON_CODE_INVALID_CLIENT_ID:
                return "Invalid client ID";
            case MqttException.REASON_CODE_CLIENT_CONNECTED:
                return "Client already connected";
            case MqttException.REASON_CODE_CLIENT_ALREADY_DISCONNECTED:
                return "Client already disconnected";
            case MqttException.REASON_CODE_CLIENT_DISCONNECTING:
                return "Client disconnecting";
            case MqttException.REASON_CODE_NO_MESSAGE_IDS_AVAILABLE:
                return "No message IDs available";
            case MqttException.REASON_CODE_WRITE_TIMEOUT:
                return "Write timeout";
            default:
                return "Unknown reason code: " + reasonCode;
        }
    }

    private PrivateKey parseECPrivateKey(String keyPem) throws Exception {
        PEMParser pemParser = null;
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Parsing EC Private Key");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Key PEM length: " + keyPem.length() + " chars");
            Log.d(TAG, "│ Key starts with: " + keyPem.substring(0, Math.min(60, keyPem.length())));
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            pemParser = new PEMParser(new StringReader(keyPem));
            Object object = pemParser.readObject();

            if (object == null) {
                throw new Exception("Could not read PEM object from key - parsed object is null");
            }

            Log.d(TAG, "  PEM object type: " + object.getClass().getName());
            Log.d(TAG, "  PEM object: " + object.getClass().getSimpleName());

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey privateKey;

            if (object instanceof PEMKeyPair) {
                Log.d(TAG, "  Detected SEC1 format (EC PRIVATE KEY)");
                PEMKeyPair keyPair = (PEMKeyPair) object;
                privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
                Log.d(TAG, "  ✓ Successfully converted SEC1 format key");
            } else if (object instanceof PrivateKeyInfo) {
                Log.d(TAG, "  Detected PKCS8 format (PRIVATE KEY)");
                privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                Log.d(TAG, "  ✓ Successfully converted PKCS8 format key");
            } else {
                throw new Exception("Unsupported key format: " + object.getClass().getName());
            }

            if (!"EC".equals(privateKey.getAlgorithm())) {
                throw new Exception("Key is not an EC key. Algorithm: " + privateKey.getAlgorithm());
            }

            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ EC Private Key Loaded Successfully");
            Log.d(TAG, "  Key algorithm: " + privateKey.getAlgorithm());
            Log.d(TAG, "  Key format: " + privateKey.getFormat());
            return privateKey;
            
        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "❌❌❌ Error Parsing EC Private Key");
            Log.e(TAG, "  Error type: " + e.getClass().getName());
            Log.e(TAG, "  Error message: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Failed to parse EC private key: " + e.getMessage(), e);
        } finally {
            if (pemParser != null) {
                try {
                    pemParser.close();
                } catch (IOException e) {
                    Log.e(TAG, "Error closing PEM parser: " + e.getMessage());
                }
            }
        }
    }

    private SSLContext createSslContext(String clientCertPem, String clientKeyPem, String rootCaPem) throws Exception {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Creating SSL Context");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Certificate Type: ECC (Elliptic Curve Cryptography)");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Log.d(TAG, "✓ Certificate factory created: X.509");

            // Load CA certificate(s) from PEM string - SUPPORTS MULTIPLE CERTIFICATES
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Loading CA Certificate(s)");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ CA PEM length: " + rootCaPem.length() + " chars");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            InputStream caInput = new ByteArrayInputStream(rootCaPem.getBytes());
            
            // Use generateCertificates (plural) to load ALL certificates
            Collection<? extends java.security.cert.Certificate> caCerts = cf.generateCertificates(caInput);
            caInput.close();
            
            Log.i(TAG, "✓✓✓ Loaded " + caCerts.size() + " CA certificate(s)");
            
            if (caCerts.isEmpty()) {
                throw new Exception("No CA certificates found in the provided PEM string");
            }

            // Store CA certificates by subject for later lookup
            ArrayList<X509Certificate> caCertsList = new ArrayList<>();
            
            // Log details of each CA certificate
            int certIndex = 0;
            for (java.security.cert.Certificate cert : caCerts) {
                X509Certificate x509Cert = (X509Certificate) cert;
                caCertsList.add(x509Cert);
                
                Log.d(TAG, "");
                Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
                Log.d(TAG, "│ CA Certificate #" + certIndex);
                Log.d(TAG, "├─────────────────────────────────────────────────────────────");
                Log.d(TAG, "│ Subject: " + x509Cert.getSubjectDN());
                Log.d(TAG, "│ Issuer: " + x509Cert.getIssuerDN());
                Log.d(TAG, "│ Valid From: " + x509Cert.getNotBefore());
                Log.d(TAG, "│ Valid Until: " + x509Cert.getNotAfter());
                Log.d(TAG, "│ Serial Number: " + x509Cert.getSerialNumber());
                Log.d(TAG, "│ Signature Algorithm: " + x509Cert.getSigAlgName());
                Log.d(TAG, "│ Public Key Algorithm: " + x509Cert.getPublicKey().getAlgorithm());
                
                // Check if certificate is currently valid
                try {
                    x509Cert.checkValidity();
                    Log.d(TAG, "│ Status: ✓ Valid");
                } catch (Exception e) {
                    Log.e(TAG, "│ Status: ❌ Invalid - " + e.getMessage());
                }
                Log.d(TAG, "└─────────────────────────────────────────────────────────────");
                certIndex++;
            }

            // Load client certificate from PEM string
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Loading Client Certificate");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Client cert PEM length: " + clientCertPem.length() + " chars");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            InputStream clientCertInput = new ByteArrayInputStream(clientCertPem.getBytes());
            X509Certificate clientCert = (X509Certificate) cf.generateCertificate(clientCertInput);
            clientCertInput.close();
            
            Log.i(TAG, "✓ Client certificate loaded successfully");
            Log.d(TAG, "  Subject: " + clientCert.getSubjectDN());
            Log.d(TAG, "  Issuer: " + clientCert.getIssuerDN());
            Log.d(TAG, "  Valid From: " + clientCert.getNotBefore());
            Log.d(TAG, "  Valid Until: " + clientCert.getNotAfter());
            Log.d(TAG, "  Serial Number: " + clientCert.getSerialNumber());
            Log.d(TAG, "  Signature Algorithm: " + clientCert.getSigAlgName());
            Log.d(TAG, "  Public Key Algorithm: " + clientCert.getPublicKey().getAlgorithm());
            
            // Check client cert validity
            try {
                clientCert.checkValidity();
                Log.d(TAG, "  Status: ✓ Valid");
            } catch (Exception e) {
                Log.e(TAG, "  Status: ❌ Invalid - " + e.getMessage());
            }

            // ✅ BUILD CERTIFICATE CHAIN: Find the intermediate CA that issued the client cert
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Building Certificate Chain");
            Log.d(TAG, "├─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Client cert issuer: " + clientCert.getIssuerDN());
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            ArrayList<java.security.cert.Certificate> certChainList = new ArrayList<>();
            certChainList.add(clientCert);
            
            // Find intermediate CA(s) by matching issuer
            String clientIssuer = clientCert.getIssuerDN().toString();
            for (X509Certificate caCert : caCertsList) {
                String caSubject = caCert.getSubjectDN().toString();
                if (clientIssuer.equals(caSubject)) {
                    certChainList.add(caCert);
                    Log.d(TAG, "  ✓ Found intermediate CA: " + caSubject);
                    
                    // Check if this intermediate is issued by another CA (build full chain)
                    String caIssuer = caCert.getIssuerDN().toString();
                    if (!caSubject.equals(caIssuer)) { // Not self-signed
                        for (X509Certificate rootCaCert : caCertsList) {
                            if (caIssuer.equals(rootCaCert.getSubjectDN().toString())) {
                                certChainList.add(rootCaCert);
                                Log.d(TAG, "  ✓ Found root CA: " + rootCaCert.getSubjectDN());
                                break;
                            }
                        }
                    }
                    break;
                }
            }
            
            java.security.cert.Certificate[] certChain = certChainList.toArray(new java.security.cert.Certificate[0]);
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ Certificate chain built with " + certChain.length + " certificate(s)");
            for (int i = 0; i < certChain.length; i++) {
                X509Certificate cert = (X509Certificate) certChain[i];
                Log.d(TAG, "  Chain[" + i + "]: " + cert.getSubjectDN());
            }

            // Parse EC private key using BouncyCastle
            PrivateKey privateKey = parseECPrivateKey(clientKeyPem);

            // Create KeyStore for client certificate and private key
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Creating KeyStore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            Log.d(TAG, "  KeyStore type: PKCS12");
            keyStore.load(null, null);
            Log.d(TAG, "  ✓ KeyStore initialized");
            
            // ✅ CRITICAL FIX: Use the full certificate chain, not just the client cert
            keyStore.setKeyEntry("client-key", privateKey, "".toCharArray(), certChain);
            Log.d(TAG, "  ✓ Client private key added to KeyStore with " + certChain.length + "-cert chain");

            // Initialize KeyManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Initializing KeyManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            Log.d(TAG, "  KeyManagerFactory algorithm: " + kmf.getAlgorithm());
            kmf.init(keyStore, "".toCharArray());
            Log.i(TAG, "  ✓ KeyManagerFactory initialized successfully");

            // Create TrustStore for CA certificate(s)
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Creating TrustStore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            Log.d(TAG, "  TrustStore type: PKCS12");
            trustStore.load(null, null);
            Log.d(TAG, "  ✓ TrustStore initialized");
            
            // Add ALL CA certificates to TrustStore
            certIndex = 0;
            for (java.security.cert.Certificate cert : caCerts) {
                trustStore.setCertificateEntry("ca-" + certIndex, cert);
                Log.d(TAG, "  ✓ CA certificate #" + certIndex + " added to TrustStore");
                certIndex++;
            }
            Log.i(TAG, "  ✓✓✓ All " + caCerts.size() + " CA certificate(s) added to TrustStore");

            // Initialize TrustManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Initializing TrustManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            Log.d(TAG, "  TrustManagerFactory algorithm: " + tmf.getAlgorithm());
            tmf.init(trustStore);
            Log.i(TAG, "  ✓ TrustManagerFactory initialized successfully");

            // Create SSLContext with TLS
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Creating SSLContext");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            Log.d(TAG, "  SSLContext protocol: " + sslContext.getProtocol());
            Log.d(TAG, "  SSLContext provider: " + sslContext.getProvider().getName());
            Log.d(TAG, "  SSLContext provider version: " + sslContext.getProvider().getVersion());
            
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ SSLContext Created Successfully ✓✓✓");
            
            // Log supported protocols and cipher suites
            try {
                String[] supportedProtocols = sslContext.getSupportedSSLParameters().getProtocols();
                Log.d(TAG, "  Supported SSL/TLS protocols: " + java.util.Arrays.toString(supportedProtocols));
                
                String[] defaultProtocols = sslContext.getDefaultSSLParameters().getProtocols();
                Log.d(TAG, "  Default SSL/TLS protocols: " + java.util.Arrays.toString(defaultProtocols));
                
                String[] cipherSuites = sslContext.getDefaultSSLParameters().getCipherSuites();
                Log.d(TAG, "  Number of default cipher suites: " + cipherSuites.length);
                Log.d(TAG, "  First 5 cipher suites: " + java.util.Arrays.toString(java.util.Arrays.copyOfRange(cipherSuites, 0, Math.min(5, cipherSuites.length))));
            } catch (Exception e) {
                Log.w(TAG, "  ⚠️ Could not log SSL parameters: " + e.getMessage());
            }
            
            return sslContext;
            
        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ SSLContext Creation Failed");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Error type: " + e.getClass().getName());
            Log.e(TAG, "║ Error message: " + e.getMessage());
            Log.e(TAG, "║ Localized message: " + e.getLocalizedMessage());
            
            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
                Log.e(TAG, "║ Cause type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
            
            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();
            
            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }
            
            throw new Exception("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    private void sendEvent(String eventName, String message) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, message);
    }
}
