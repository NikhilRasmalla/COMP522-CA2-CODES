import javax.crypto.*;
import java.security.*;

public class HMACDTSK {

    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        SecretKey sk = kg.generateKey();

        System.out.println("Step 1: Generating Secret Key using HmacSHA256");
        System.out.println("Secret Key: " + toHexString(sk.getEncoded()));

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sk);

        System.out.println("\nStep 2: Initializing MAC with the Secret Key");

        // Different texts for MAC calculation
        String text1 = "APJAbdulKalam";
        String text2 = "ISRO";

        // Calculate MAC for different texts
        byte[] result1 = calculateMAC(mac, text1);
        byte[] result2 = calculateMAC(mac, text2);

        System.out.println("\nStep 3: Calculating MAC for different texts");
        System.out.println("Text 1: " + text1);
        System.out.println("Result 1: " + toHexString(result1));

        System.out.println("\nText 2: " + text2);
        System.out.println("Result 2: " + toHexString(result2));
    }

    private static byte[] calculateMAC(Mac mac, String text) {
        return mac.doFinal(text.getBytes());
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
