import javax.crypto.*;
import java.security.*;

public class HMACSTSK {

    public static void main(String[] args) throws Exception {
        // Secret message
        String secretMessage = "APJAbdulKalam";

        System.out.println("Secret Message: " + secretMessage);

        System.out.println("\nStep 1: Generating Secret Key using HmacSHA256");

        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        SecretKey sk = kg.generateKey();

        System.out.println("Secret Key: " + toHexString(sk.getEncoded()));

        System.out.println("\nStep 2: Initializing MAC with the Secret Key");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sk);

        System.out.println("\nStep 3: Calculating HMAC for the same text multiple times");

        // Calculate HMAC for the same text multiple times
        byte[] result1 = calculateHMAC(mac, secretMessage);
        byte[] result2 = calculateHMAC(mac, secretMessage);

        System.out.println("Result 1: " + toHexString(result1));
        System.out.println("Result 2: " + toHexString(result2));
    }

    private static byte[] calculateHMAC(Mac mac, String message) {
        return mac.doFinal(message.getBytes());
    }

    private static String toHexString(byte[] block) {
        StringBuilder buf = new StringBuilder();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            buf.append(String.format("%02X", block[i]));
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
