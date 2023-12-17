import { StatusBar } from "expo-status-bar";
import { Button, StyleSheet, Text, View } from "react-native";
import { testEncryptionDecryption, testSigningVerification } from "./s";

export default function App() {
  return (
    <View style={styles.container}>
      <Text>Open up App.js to start working on your app now!</Text>
      <Button
        title="Test Encryption Decryption"
        onPress={testEncryptionDecryption}
      />
      <Button
        title="Test Signing Verification"
        onPress={testSigningVerification}
      />
      <StatusBar style="auto" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
