import java.security.*; 

import javax.crypto.*; 

  

public class MessageAuthenticationProtocol { 

     

    public static void main(String[] args) throws Exception { 

        // Sender's Actions 

        String message = "APJAbdulKalam";

  

        // Calculate SHA-1 digest 

        byte[] digest = calculateSHA1(message); 

        System.out.println("Original Message: " + message); 

        System.out.println("SHA-1 Digest: " + bytesToHex(digest)); 

  

        // Generate RSA key pair 

        KeyPair keyPair = generateKeyPair(); 

        System.out.println("RSA Key Pair Generated."); 

  

        // Encrypt digest with private key 

        byte[] encryptedDigest = encryptWithPrivateKey(digest, keyPair.getPrivate()); 

        System.out.println("Digest Encrypted with Private Key: " + bytesToHex(encryptedDigest)); 

  

        // Pass the original message, encrypted digest, and public key to the Verifier 

        passToVerifier(message, encryptedDigest, keyPair.getPublic()); 

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

        System.out.println("Digest Decrypted with Public Key: " + bytesToHex(decryptedDigest)); 

  

        // Calculate SHA-1 digest from received message 

        byte[] receivedDigest = calculateSHA1(message); 

        System.out.println("Recalculated SHA-1 Digest from Received Message: " + bytesToHex(receivedDigest)); 

  

        // Compare and print the two digests to verify if they match 

        if (MessageDigest.isEqual(decryptedDigest, receivedDigest)) { 

            System.out.println("Message integrity verified. Digests match!"); 

        } else { 

            System.out.println("Message integrity verification failed. Digests do not match!"); 

        } 

    } 

  

    // Helper method to convert byte array to hexadecimal string (for easier printing) 

    public static String bytesToHex(byte[] hash) { 

        StringBuilder hexString = new StringBuilder(2 * hash.length); 

        for (byte b : hash) { 

            String hex = Integer.toHexString(0xff & b); 

            if (hex.length() == 1) { 

                hexString.append('0'); 

            } 

            hexString.append(hex); 

        } 

        return hexString.toString(); 

    } 

} 

