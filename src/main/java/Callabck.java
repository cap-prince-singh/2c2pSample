import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

public class Callabck {

    public static void main(String[] args) {

        String secretKey = "33949FCDF8791E4DC33E186BA30C93232870F093CCC2D4CCC4CE215B819B6550";
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI0MTExMTFYWFhYWFgxMTExIiwiY2FyZFRva2VuIjoiMTIwNDIyMTg0MDM0NDUwNDA0MzAiLCJsb3lhbHR5UG9pbnRzIjpudWxsLCJtZXJjaGFudElEIjoiNzAyNzAyMDAwMDAxODc1IiwiaW52b2ljZU5vIjoiMTY1Mjc3Nzc2OTc1MVFWUFFDV0YiLCJhbW91bnQiOjU1LjAsIm1vbnRobHlQYXltZW50IjpudWxsLCJ1c2VyRGVmaW5lZDEiOiIiLCJ1c2VyRGVmaW5lZDIiOiIiLCJ1c2VyRGVmaW5lZDMiOiIiLCJ1c2VyRGVmaW5lZDQiOiIiLCJ1c2VyRGVmaW5lZDUiOiIiLCJjdXJyZW5jeUNvZGUiOiJTR0QiLCJyZWN1cnJpbmdVbmlxdWVJRCI6IiIsInRyYW5SZWYiOiI0OTE1MTEzIiwicmVmZXJlbmNlTm8iOiI0NTQyNzM1IiwiYXBwcm92YWxDb2RlIjoiNzMxMjMyIiwiZWNpIjoiMDUiLCJ0cmFuc2FjdGlvbkRhdGVUaW1lIjoiMjAyMjA1MTcxNjU3NTkiLCJhZ2VudENvZGUiOiJCQkwiLCJjaGFubmVsQ29kZSI6IlZJIiwiaXNzdWVyQ291bnRyeSI6IlVTIiwiaXNzdWVyQmFuayI6IkJBTksiLCJpbnN0YWxsbWVudE1lcmNoYW50QWJzb3JiUmF0ZSI6bnVsbCwiY2FyZFR5cGUiOiJDUkVESVQiLCJpZGVtcG90ZW5jeUlEIjoiIiwicGF5bWVudFNjaGVtZSI6IlZJIiwicmVzcENvZGUiOiIwMDAwIiwicmVzcERlc2MiOiJTdWNjZXNzIn0.qZOIb8LkByf0T76T071vzogvOWn8rQF2FU-tD3tPfzY";
            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        HashMap<String, String> data = new HashMap<>();
        responseData.forEach((s, claim) -> {
            data.put(s,claim.asString());
        });

        System.out.println(data);
        String s = new Gson().toJson(data);
        System.out.println(s);
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
