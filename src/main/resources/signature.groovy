import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hashes the string contents (assumed to be UTF-8) using the SHA-256
 * algorithm.
 */
public static byte[] hash(String text) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes("UTF-8"));
        return md.digest();
    } catch (Exception e) {
        throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
    }
}

/**
 * Hashes the byte array using the SHA-256 algorithm.
 */
public static byte[] hash(byte[] data) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data);
        return md.digest();
    } catch (Exception e) {
        throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
    }
}

public static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder(data.length * 2);
    for (int i = 0; i < data.length; i++) {
        String hex = Integer.toHexString(data[i]);
        if (hex.length() == 1) {
            // Append leading zero.
            sb.append("0");
        } else if (hex.length() == 8) {
            // Remove ff prefix from negative numbers.
            hex = hex.substring(6);
        }
        sb.append(hex);
    }
    return sb.toString().toLowerCase(Locale.getDefault());
}

public String getTimeStamp() {
    DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    return dateFormat.format(new Date());
}

public String getDate() {
    DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    return dateFormat.format(new Date());
}


public String prepareCanonicalRequest(String xAmzDate) {

	String httpMethodName = "POST"; //message.getInboundProperty('http.method');
	String canonicalURI = "/2015-03-31/functions/hello-python/invocations";
	String strSignedHeader = ""; 

	TreeMap<String, String> queryParameters = [];

    StringBuilder canonicalURL = new StringBuilder("");

    canonicalURL.append(httpMethodName).append("\n");

    canonicalURI = canonicalURI == null || canonicalURI.trim().isEmpty() ? "/" : canonicalURI;
    canonicalURL.append(canonicalURI).append("\n");

    StringBuilder queryString = new StringBuilder("");
    if (queryParameters != null && !queryParameters.isEmpty()) {
        for (Map.Entry<String, String> entrySet : queryParameters.entrySet()) {
            String key = entrySet.getKey();
            String value = entrySet.getValue();
            queryString.append(key).append("=").append(encodeParameter(value)).append("&");
        }

        queryString.deleteCharAt(queryString.lastIndexOf("&"));

        queryString.append("\n");
    } else {
        queryString.append("\n");
    }
    canonicalURL.append(queryString);

	TreeMap<String, String> awsHeaders = [];
	awsHeaders.put("x-amz-date", xAmzDate);
	awsHeaders.put("host", "lambda.us-east-1.amazonaws.com");
	awsHeaders.put("content-type", "application/json");
	awsHeaders.put("content-length", flowVars.originalPayload.length());

	
    StringBuilder signedHeaders = new StringBuilder("");
    if (awsHeaders != null && !awsHeaders.isEmpty()) {
        for (Map.Entry<String, String> entrySet : awsHeaders.entrySet()) {
            String key = entrySet.getKey().toLowerCase();
            String value = entrySet.getValue();
            signedHeaders.append(key).append(";");
            canonicalURL.append(key).append(":").append(value).append("\n");
        }
		canonicalURL.append("\n");
    } else {
        canonicalURL.append("\n");
    }

    flowVars.strSignedHeader = signedHeaders.substring(0, signedHeaders.length() - 1).toLowerCase();
    canonicalURL.append(flowVars.strSignedHeader).append("\n");

	payload = flowVars.originalPayload == null ? "" : flowVars.originalPayload;
	
	byte[] contentHash = hash(payload);
	String contentHashString = toHex(contentHash);

    canonicalURL.append(contentHashString);

    return canonicalURL.toString();
}

public String prepareStringToSign(String canonicalURL, String xAmzDate) {
    String stringToSign = "";
    stringToSign = "AWS4-HMAC-SHA256" + "\n";
    stringToSign += xAmzDate + "\n";
    stringToSign += getDate() + "/" + flowVars.region + "/" + flowVars.service + "/" + "aws4_request" + "\n";
    stringToSign += toHex(hash(canonicalURL));
    return stringToSign;
}

public byte[] HmacSHA256(byte[] key, String data) throws Exception {
    String algorithm = "HmacSHA256";
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key, algorithm));
    return mac.doFinal(data.getBytes("UTF8"));
}

public byte[] getSignatureKey(String key, String date, String regionName, String serviceName) throws Exception {
    byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
    byte[] kDate = HmacSHA256(kSecret, date);
    byte[] kRegion = HmacSHA256(kDate, regionName);
    byte[] kService = HmacSHA256(kRegion, serviceName);
    byte[] kSigning = HmacSHA256(kService, "aws4_request");
    return kSigning;
}

xAmzDate = getTimeStamp();
currentDate = getDate();

public String buildAuthorizationString(String strSignature) {
    return "AWS4-HMAC-SHA256" + " " + "Credential=" + flowVars.accessKey + "/" + currentDate + "/" + flowVars.region + "/" + flowVars.service + "/" + "aws4_request" + ", " + "SignedHeaders=" + flowVars.strSignedHeader + ", " + "Signature=" + strSignature;
}
 
flowVars.credentialDate = currentDate;
flowVars.amzDate = xAmzDate;

/* Task 1 - Create a Canonical Request */
String canonicalURL = prepareCanonicalRequest(xAmzDate);
flowVars.canonicalURL = canonicalURL

/* Task 2 - Create a String to Sign */
String stringToSign = prepareStringToSign(canonicalURL, xAmzDate);
flowVars.stringToSign = stringToSign

/* Task 3 - Calculate the Signature */
byte[] signatureKey = getSignatureKey(flowVars.secretKey,currentDate,flowVars.region,flowVars.service);
byte[] signature = HmacSHA256(signatureKey, stringToSign);
String strHexSignature = toHex(signature);

/* Task 4 - Add the Signing Information to the Request */
message.setOutboundProperty('Authorization', buildAuthorizationString(strHexSignature));
message.setOutboundProperty('content-type', 'application/json');
message.setOutboundProperty('x-amz-date', xAmzDate);
message.setOutboundProperty('host', flowVars.service + '.' + flowVars.region + '.amazonaws.com');

return payload;