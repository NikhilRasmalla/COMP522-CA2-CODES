import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class DHKeyAgreement4 {
    private DHKeyAgreement4() {}

    public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with a 2048-bit key size
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        DHParameterSpec dhParamShared = ((DHPublicKey) aliceKpair.getPublic()).getParams();

        // Bob, Carol, and David create their own DH key pairs using the same params as Alice
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamShared);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
        carolKpairGen.initialize(dhParamShared);
        KeyPair carolKpair = carolKpairGen.generateKeyPair();

        KeyPairGenerator davidKpairGen = KeyPairGenerator.getInstance("DH");
        davidKpairGen.initialize(dhParamShared);
        KeyPair davidKpair = davidKpairGen.generateKeyPair();

        // Alice, Bob, Carol, and David initialize KeyAgreement
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
        carolKeyAgree.init(carolKpair.getPrivate());

        KeyAgreement davidKeyAgree = KeyAgreement.getInstance("DH");
        davidKeyAgree.init(davidKpair.getPrivate());

        // Calculating the intermediate keys
        Key DA = aliceKeyAgree.doPhase(davidKpair.getPublic(), false);
        Key AB = bobKeyAgree.doPhase(aliceKpair.getPublic(), false);
        Key BC = carolKeyAgree.doPhase(bobKpair.getPublic(), false);
        Key CD = davidKeyAgree.doPhase(carolKpair.getPublic(), false);

        // Computing the combined keys
        Key CDA = aliceKeyAgree.doPhase(CD, false);
        Key DAB = bobKeyAgree.doPhase(DA, false);
        Key ABC = carolKeyAgree.doPhase(AB, false);
        Key BCD = davidKeyAgree.doPhase(BC, false);

        Key BCDA = aliceKeyAgree.doPhase(BCD, true); // Alice's secret
        Key CDAB = bobKeyAgree.doPhase(CDA, true); // Bob's secret
        Key ABCD = carolKeyAgree.doPhase(DAB, true); // Carol's secret
        Key DABC = davidKeyAgree.doPhase(ABC, true); // David's secret

        // Alice, Bob, Carol, and David generate their secrets
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        byte[] davidSharedSecret = davidKeyAgree.generateSecret();

        // Printing the secrets
        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
        System.out.println("Bob secret: " + toHexString(bobSharedSecret));
        System.out.println("Carol secret: " + toHexString(carolSharedSecret));
        System.out.println("David secret: " + toHexString(davidSharedSecret));

        // Comparing secrets
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            System.out.println("Alice and Bob differ");
        else
            System.out.println("Alice and Bob are the same");

        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            System.out.println("Bob and Carol differ");
        else
            System.out.println("Bob and Carol are the same");

        if (!java.util.Arrays.equals(carolSharedSecret, davidSharedSecret))
            System.out.println("Carol and David differ");
        else
            System.out.println("Carol and David are the same");

        if (!java.util.Arrays.equals(davidSharedSecret, aliceSharedSecret))
            System.out.println("David and Alice differ");
        else
            System.out.println("David and Alice are the same");
    }

    // Conversion functions for printing byte arrays in hex format
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
