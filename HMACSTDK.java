import javax.crypto.*;
import java.security.*;

public class HMACSTDK {

    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");

        // Generate two different secret keys
        SecretKey sk1 = kg.generateKey();
        SecretKey sk2 = kg.generateKey();

        String secretMessage = "APJAbdulKalam";
        System.out.println("Step 1: Generating Two Different Secret Keys");

        Mac mac1 = Mac.getInstance("HmacSHA256");
        Mac mac2 = Mac.getInstance("HmacSHA256");

        // Initialize Mac objects with the respective keys and secret message
        mac1.init(sk1);
        byte[] result1 = mac1.doFinal(secretMessage.getBytes());

        mac2.init(sk2);
        byte[] result2 = mac2.doFinal(secretMessage.getBytes());

        System.out.println("\nStep 2: Calculating HMAC-SHA256 for the secret message '" + secretMessage + "'");
        System.out.println("Secret Message: " + secretMessage);
        System.out.println("Key 1: " + bytesToHex(sk1.getEncoded()));
        System.out.println("Result 1: " + bytesToHex(result1));

        System.out.println("\nKey 2: " + bytesToHex(sk2.getEncoded()));
        System.out.println("Result 2: " + bytesToHex(result2));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xff & aByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
            hexString.append(':');
        }
        return hexString.substring(0, hexString.length() - 1).toUpperCase();
    }
}
