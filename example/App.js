import React, { useState } from 'react';
import {
    SafeAreaView,
    ScrollView,
    StyleSheet,
    Text,
    TextInput,
    TouchableOpacity,
    View,
    Alert,
} from 'react-native';
import { generateCSR, getPublicKey, deleteKeyPair, hasKeyPair, ECCCurve } from 'react-native-ecc-csr';

const App = () => {
    const [commonName, setCommonName] = useState('5dab25dd-7d0a-4a03-94c3-39f935c0a48a');
    const [serialNumber, setSerialNumber] = useState('APCBPGN2202-AF250300028');
    const [country, setCountry] = useState('US');
    const [state, setState] = useState('Nevada');
    const [locality, setLocality] = useState('Reno');
    const [organization, setOrganization] = useState('Generac');
    const [organizationalUnit, setOrganizationalUnit] = useState('PWRview');
    const [ipAddress, setIpAddress] = useState('10.10.10.10');
    const [selectedCurve, setSelectedCurve] = useState('P-384');
    const [csr, setCSR] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [loading, setLoading] = useState(false);

    const handleGenerateCSR = async () => {
        try {
            setLoading(true);
            setCSR('');
            setPublicKey('');

            const result = await generateCSR({
                commonName,
                serialNumber,
                country,
                state,
                locality,
                organization,
                organizationalUnit,
                ipAddress,
                curve: selectedCurve,
                keyAlias: 'EXAMPLE_KEY',
            });

            setCSR(result.csr);
            setPublicKey(result.publicKey);
            Alert.alert('Success', 'CSR generated successfully!');
        } catch (error) {
            Alert.alert('Error', error.message);
        } finally {
            setLoading(false);
        }
    };

    const handleGetPublicKey = async () => {
        try {
            const exists = await hasKeyPair('EXAMPLE_KEY');
            if (!exists) {
                Alert.alert('Error', 'No key pair found. Generate a CSR first.');
                return;
            }

            const key = await getPublicKey('EXAMPLE_KEY');
            setPublicKey(key);
            Alert.alert('Success', 'Public key retrieved!');
        } catch (error) {
            Alert.alert('Error', error.message);
        }
    };

    const handleDeleteKey = async () => {
        try {
            await deleteKeyPair('EXAMPLE_KEY');
            setCSR('');
            setPublicKey('');
            Alert.alert('Success', 'Key pair deleted!');
        } catch (error) {
            Alert.alert('Error', error.message);
        }
    };

    const handleCheckKey = async () => {
        try {
            const exists = await hasKeyPair('EXAMPLE_KEY');
            Alert.alert('Key Status', exists ? 'Key pair exists' : 'No key pair found');
        } catch (error) {
            Alert.alert('Error', error.message);
        }
    };

    return (
        <SafeAreaView style={styles.container}>
            <ScrollView style={styles.scrollView}>
                <Text style={styles.title}>ECC CSR Generator</Text>

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>Subject Information</Text>

                    <Text style={styles.label}>Common Name (CN) *</Text>
                    <TextInput
                        style={styles.input}
                        value={commonName}
                        onChangeText={setCommonName}
                        placeholder="Enter common name"
                    />

                    <Text style={styles.label}>Serial Number</Text>
                    <TextInput
                        style={styles.input}
                        value={serialNumber}
                        onChangeText={setSerialNumber}
                        placeholder="Enter serial number"
                    />

                    <Text style={styles.label}>Country (C)</Text>
                    <TextInput
                        style={styles.input}
                        value={country}
                        onChangeText={setCountry}
                        placeholder="US"
                        maxLength={2}
                    />

                    <Text style={styles.label}>State/Province (ST)</Text>
                    <TextInput
                        style={styles.input}
                        value={state}
                        onChangeText={setState}
                        placeholder="Enter state"
                    />

                    <Text style={styles.label}>Locality/City (L)</Text>
                    <TextInput
                        style={styles.input}
                        value={locality}
                        onChangeText={setLocality}
                        placeholder="Enter city"
                    />

                    <Text style={styles.label}>Organization (O)</Text>
                    <TextInput
                        style={styles.input}
                        value={organization}
                        onChangeText={setOrganization}
                        placeholder="Enter organization"
                    />

                    <Text style={styles.label}>Organizational Unit (OU)</Text>
                    <TextInput
                        style={styles.input}
                        value={organizationalUnit}
                        onChangeText={setOrganizationalUnit}
                        placeholder="Enter organizational unit"
                    />

                    <Text style={styles.label}>IP Address (SAN)</Text>
                    <TextInput
                        style={styles.input}
                        value={ipAddress}
                        onChangeText={setIpAddress}
                        placeholder="10.10.10.10"
                        keyboardType="numeric"
                    />
                </View>

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>ECC Curve Selection</Text>
                    <View style={styles.curveButtons}>
                        {['P-256', 'P-384', 'P-521'].map((curve) => (
                            <TouchableOpacity
                                key={curve}
                                style={[
                                    styles.curveButton,
                                    selectedCurve === curve && styles.curveButtonSelected,
                                ]}
                                onPress={() => setSelectedCurve(curve)}
                            >
                                <Text
                                    style={[
                                        styles.curveButtonText,
                                        selectedCurve === curve && styles.curveButtonTextSelected,
                                    ]}
                                >
                                    {curve}
                                </Text>
                            </TouchableOpacity>
                        ))}
                    </View>
                </View>

                <View style={styles.section}>
                    <TouchableOpacity
                        style={[styles.button, styles.primaryButton, loading && styles.buttonDisabled]}
                        onPress={handleGenerateCSR}
                        disabled={loading}
                    >
                        <Text style={styles.buttonText}>
                            {loading ? 'Generating...' : 'Generate CSR'}
                        </Text>
                    </TouchableOpacity>

                    <View style={styles.buttonRow}>
                        <TouchableOpacity style={[styles.button, styles.smallButton]} onPress={handleGetPublicKey}>
                            <Text style={styles.buttonText}>Get Public Key</Text>
                        </TouchableOpacity>

                        <TouchableOpacity style={[styles.button, styles.smallButton]} onPress={handleCheckKey}>
                            <Text style={styles.buttonText}>Check Key</Text>
                        </TouchableOpacity>

                        <TouchableOpacity
                            style={[styles.button, styles.smallButton, styles.dangerButton]}
                            onPress={handleDeleteKey}
                        >
                            <Text style={styles.buttonText}>Delete Key</Text>
                        </TouchableOpacity>
                    </View>
                </View>

                {csr ? (
                    <View style={styles.section}>
                        <Text style={styles.sectionTitle}>Generated CSR</Text>
                        <ScrollView style={styles.output} horizontal>
                            <Text style={styles.outputText}>{csr}</Text>
                        </ScrollView>
                    </View>
                ) : null}

                {publicKey ? (
                    <View style={styles.section}>
                        <Text style={styles.sectionTitle}>Public Key</Text>
                        <ScrollView style={styles.output} horizontal>
                            <Text style={styles.outputText}>{publicKey}</Text>
                        </ScrollView>
                    </View>
                ) : null}
            </ScrollView>
        </SafeAreaView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#f5f5f5',
    },
    scrollView: {
        flex: 1,
        padding: 16,
    },
    title: {
        fontSize: 24,
        fontWeight: 'bold',
        marginBottom: 20,
        textAlign: 'center',
    },
    section: {
        backgroundColor: 'white',
        borderRadius: 8,
        padding: 16,
        marginBottom: 16,
    },
    sectionTitle: {
        fontSize: 18,
        fontWeight: '600',
        marginBottom: 12,
    },
    label: {
        fontSize: 14,
        fontWeight: '500',
        marginTop: 8,
        marginBottom: 4,
    },
    input: {
        borderWidth: 1,
        borderColor: '#ddd',
        borderRadius: 4,
        padding: 12,
        fontSize: 14,
        backgroundColor: '#fff',
    },
    curveButtons: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    curveButton: {
        flex: 1,
        padding: 12,
        marginHorizontal: 4,
        borderRadius: 4,
        borderWidth: 2,
        borderColor: '#007AFF',
        alignItems: 'center',
    },
    curveButtonSelected: {
        backgroundColor: '#007AFF',
    },
    curveButtonText: {
        color: '#007AFF',
        fontWeight: '600',
    },
    curveButtonTextSelected: {
        color: 'white',
    },
    button: {
        padding: 16,
        borderRadius: 8,
        alignItems: 'center',
        marginTop: 8,
    },
    primaryButton: {
        backgroundColor: '#007AFF',
    },
    smallButton: {
        flex: 1,
        marginHorizontal: 4,
        backgroundColor: '#5856D6',
    },
    dangerButton: {
        backgroundColor: '#FF3B30',
    },
    buttonDisabled: {
        opacity: 0.5,
    },
    buttonText: {
        color: 'white',
        fontSize: 16,
        fontWeight: '600',
    },
    buttonRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    output: {
        maxHeight: 200,
        backgroundColor: '#f9f9f9',
        borderRadius: 4,
        padding: 12,
    },
    outputText: {
        fontFamily: 'Courier',
        fontSize: 12,
    },
});

export default App;