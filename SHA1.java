import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1 {

    public static void main(String[] args) {

        String originalString = "APJAbdulKalam";

        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(originalString.getBytes());

            // Convert byte array to a string of hexadecimal values
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            System.out.println("Step 1: Original String: " + originalString);
            System.out.println("Step 2: Calculating SHA-1 Hash");
            System.out.println("SHA-1 Hash: " + hexString.toString());

        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-1 algorithm not available.");
        }
    }
}
