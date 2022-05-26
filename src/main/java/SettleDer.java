import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.EncryptedJWT;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SettleDer {

    public static void main(String[] args)
            throws IOException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        Security.setProperty("crypto.policy", "unlimited");

        String paymentRequest =
                "<PaymentProcessRequest>" +
                        "<version>3.8</version>" +
                        "<merchantID>702702000001875</merchantID>" +
                        "<processType>I</processType>" +
                        "<invoiceNo>1653487589240I9BXCGM</invoiceNo>" +
                        "<actionAmount>150.00</actionAmount>" +
                "</PaymentProcessRequest>";

        FileInputStream is = new FileInputStream(
                "/Users/prince/Builds/CAP/2c2psample/2c2p/jwt.cer"); ////2c2p public cert key

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(is);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();

        File file = new File("/Users/prince/Builds/CAP/2c2psample/self/script/private.der");
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);

        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        java.security.interfaces.RSAPrivateKey jwsPrivateKey = (java.security.interfaces.RSAPrivateKey) kf
                .generatePrivate(spec);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(paymentRequest));
        jwe.encrypt(new RSAEncrypter(jweRsaPubKey, cek));
        String jwePayload = jwe.serialize();

        RSASSASigner signer = new RSASSASigner(jwsPrivateKey);
        JWSHeader headerc = new JWSHeader(JWSAlgorithm.PS256);
        JWSObject jwsObject = new JWSObject(headerc, new Payload(jwePayload));
        jwsObject.sign(signer);
      String jwsPayload = jwsObject.serialize();

        JSONObject requestData = new JSONObject();
        requestData.put("payload", jwsPayload);

        try {
            String endpoint = "https://demo2.2c2p.com/2C2PFrontend/PaymentAction/2.0/action";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(jwsPayload);
            wr.flush();
            wr.close();
            System.out.println("ABC  " + requestData.toJSONString());

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            System.out.println(response);
            JWSObject jwsObjectRes = JWSObject.parse(response.toString());

            RSAKey rsaJWERes = RSAKey.parse(jwePubKey);
            RSAPublicKey jweRsaPubKeyRes = rsaJWERes.toRSAPublicKey();

            boolean verified = jwsObjectRes.verify(new RSASSAVerifier(jweRsaPubKeyRes));

            if (verified) {
                JWEObject jweRes = EncryptedJWT.parse(jwsObjectRes.getPayload().toString());
                jweRes.decrypt(new RSADecrypter(jwsPrivateKey));
                String responsePayload = jweRes.getPayload().toString();
                System.out.println(responsePayload);
            } else {
                System.out.println("panic");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}