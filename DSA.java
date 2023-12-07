import java.security.*;

public class DSA {

    public static void main(String[] args) throws Exception {
        // Sample message
        String message = "APJAbdulKalam";

        int keyLength = 1024;
        System.out.println("Original Message: " + message);
        System.out.println("Step 1: Generating DSA Key Pair with key length of " + keyLength + " bits");

        // Generate DSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstanceStrong(); // Use strong random
        keyGen.initialize(keyLength, random);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Display DSA Keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("\nDSA Public Key: " + bytesToHex(publicKey.getEncoded()));
        System.out.println("\nDSA Private Key: " + bytesToHex(privateKey.getEncoded()));

        System.out.println("\nStep 2: Creating Digital Signature for the message");

        // Create a digital signature for the message
        byte[] digitalSignature = createDigitalSignature(message, privateKey);

        System.out.println("Step 3: Passing the message, digital signature, and public key to the Verifier");

        // Pass the message, digital signature, and public key to the Verifier
        passToVerifier(message, digitalSignature, publicKey);
    }

    // Method to create a digital signature
    public static byte[] createDigitalSignature(String message, PrivateKey privateKey) throws Exception {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes());
        return dsa.sign();
    }

    // Method to verify the digital signature
    public static void passToVerifier(String message, byte[] digitalSignature, PublicKey publicKey) throws Exception {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes());

        // Verify the signature
        boolean verified = dsa.verify(digitalSignature);

        // Print verification result
        if (verified) {
            System.out.println("Message integrity verified. Digital Signature is valid!");
        } else {
            System.out.println("Message integrity verification failed. Digital Signature is not valid!");
        }
    }

    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
