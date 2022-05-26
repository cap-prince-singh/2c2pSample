import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class GenerateToken {

    public static void main(String[] args) {

        String token = "";
        String secretKey = "33949FCDF8791E4DC33E186BA30C93232870F093CCC2D4CCC4CE215B819B6550";
        String[] paymentChannel = {"CC"};

        HashMap<String, Object> payload = new HashMap<>();

        String register = "https://orchestrator.crm-nightly-new.cc.capillarytech.com/orchestrator/payments/webhooks/2c2p/register-callback";
        String fuelling = "https://orchestrator.crm-nightly-new.cc.capillarytech.com/orchestrator/payments/webhooks/2c2p/fuelling-callback";
        String mock = "https://94a48384-b3d4-40a1-8f1d-e60692ecf8a9.mock.pstmn.io";

        String extC = "CAP_88b95263-dce9-11ec-8cbb-3a9eb2570bfe";

        payload.put("backendReturnUrl", mock + "?orgId=50906&userId=374831221&paymentProvider=2c2p123&isDefaultCard=true&extCorrelationID=" + extC);
        payload.put("merchantID", "702702000001875");

        payload.put("invoiceNo", "1653565612");
        payload.put("amount", 200.00);
        payload.put("cardTokens", Arrays.asList("28042218115231031647"));

        payload.put("description", "card test");
        payload.put("currencyCode", "SGD");
        payload.put("tokenize", true);
        payload.put("paymentChannel", paymentChannel);
        payload.put("storeCard", "Y");
        payload.put("paymentExpiry", "2022-06-26 12:00:00");

        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            token = JWT.create()
                    .withPayload(payload).sign(algorithm);

        } catch (JWTCreationException | IllegalArgumentException e) {
            //Invalid Signing configuration / Couldn't convert Claims.
            e.printStackTrace();
        }

        JSONObject requestData = new JSONObject();
        requestData.put("payload", token);

        try {
            String endpoint = "https://sandbox-pgw.2c2p.com/payment/4.1/PaymentToken";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(requestData.toString());
            wr.flush();
            wr.close();


            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            JSONParser parser = new JSONParser();
            JSONObject responseJSON = (JSONObject) parser.parse(response.toString());
            String responseToken = responseJSON.get("payload").toString();

            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(responseToken);   //verify signature
            DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
            Map<String, Claim> responseData = jwt.getClaims();
            String paymentToken = responseData.get("paymentToken").asString();

            //paymentToken -> {JsonNodeClaim@3050} ""kSAops9Zwhos8hSTSeLTUZBQPG0it8C9onkziF7YwrTaN6Ojrs3Bq86PDH0CvKY4j+pF55ffrKl8IKpWqpx923Rqgmpa1b5zaSsrS3qvJfpPA8iEhgZVthsmiSw+Y9uv""

            HashMap<String, Object> capture = new HashMap<>();

            capture.put("paymentToken", paymentToken);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
