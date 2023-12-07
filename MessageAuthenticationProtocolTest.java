import java.security.*;
import javax.crypto.*;

public class MessageAuthenticationProtocolTest {

    public static void main(String[] args) throws Exception {
        // Sample Messages
        String successfulMessage = "APJAbdulKalam";
        String alteredMessage = "ISRO"; // Altered message
        String differentMessage = "Science"; // Different message

        // Calculate SHA-1 digest for each message
        byte[] successfulDigest = calculateSHA1(successfulMessage);
        byte[] alteredDigest = calculateSHA1(alteredMessage);
        byte[] differentDigest = calculateSHA1(differentMessage);

        System.out.println("Step 1: Calculating SHA-1 digests");
        System.out.println("Successful Message Digest: " + bytesToHex(successfulDigest));
        System.out.println("Altered Message Digest: " + bytesToHex(alteredDigest));
        System.out.println("Different Message Digest: " + bytesToHex(differentDigest));

        // Generate RSA key pair
        KeyPair keyPair = generateKeyPair();

        System.out.println("\nStep 2: Generating RSA Key Pair");

        // Encrypt successful message's digest with private key
        byte[] encryptedDigest = encryptWithPrivateKey(successfulDigest, keyPair.getPrivate());

        System.out.println("Encrypted Digest: " + bytesToHex(encryptedDigest));

        // Pass the original successful message, encrypted digest, and public key to the Verifier
        System.out.println("\nStep 3: Passing to Verifier");
        passToVerifier(successfulMessage, encryptedDigest, keyPair.getPublic());

        // Pass the altered message, encrypted digest, and public key to the Verifier
        System.out.println("\nPassing Altered Message to Verifier");
        passToVerifier(alteredMessage, encryptedDigest, keyPair.getPublic());

        // Pass the different message, encrypted digest, and public key to the Verifier
        System.out.println("\nPassing Different Message to Verifier");
        passToVerifier(differentMessage, encryptedDigest, keyPair.getPublic());
    } 

    // Calculate SHA-1 digest 
    public static byte[] calculateSHA1(String message) throws Exception { 
        MessageDigest digest = MessageDigest.getInstance("SHA-1"); 
        return digest.digest(message.getBytes()); 
    } 

    // Generate RSA key pair 
    public static KeyPair generateKeyPair() throws Exception { 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); 
        keyGen.initialize(2048); // Adjust key size as needed 
        return keyGen.generateKeyPair(); 
    } 

    // Encrypt digest with private key 
    public static byte[] encryptWithPrivateKey(byte[] digest, PrivateKey privateKey) throws Exception { 
        Cipher cipher = Cipher.getInstance("RSA"); 
        cipher.init(Cipher.ENCRYPT_MODE, privateKey); 
        return cipher.doFinal(digest); 
    } 

    // Pass the original message, encrypted digest, and public key to the Verifier 
    public static void passToVerifier(String message, byte[] encryptedDigest, PublicKey publicKey) throws Exception { 
        // Verifier's Actions 
        Cipher cipher = Cipher.getInstance("RSA"); 
        cipher.init(Cipher.DECRYPT_MODE, publicKey); 

        // Decrypt the encrypted digest 
        byte[] decryptedDigest = cipher.doFinal(encryptedDigest); 

        // Calculate SHA-1 digest from received message 
        byte[] receivedDigest = calculateSHA1(message); 

        // Compare and print the two digests to verify if they match 
        if (MessageDigest.isEqual(decryptedDigest, receivedDigest)) { 
            System.out.println("For Message: '" + message + "' - Message integrity verified. Digests match!"); 
        } else { 
            System.out.println("For Message: '" + message + "' - Message integrity verification failed. Digests do not match!"); 
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
