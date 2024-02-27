// This example demonstrates how to create a pre-signed URL for an Amazon S3 object using Ballerina.
// Based on https://github.com/ballerina-platform/module-ballerinax-aws.s3
// Refer to https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html for more information.
import ballerina/crypto;
import ballerina/io;
import ballerina/jballerina.java;
import ballerina/lang.array;
import ballerina/regex;
import ballerina/time;
import ballerina/url;

public function main() returns error? {
    string accessKeyId = ""; // AWS access key
    string secretAccessKey = ""; // AWS secret key
    string region = ""; // AWS region
    string bucketName = ""; // S3 bucket name
    string key = ""; // S3 object key
    string httpMethod = ""; // HTTP method | GET for download, PUT for upload
    int expiresIn = 86400; // Expiry time in seconds
    
    string presignedURL = check createPresignedURL(accessKeyId, secretAccessKey, region, bucketName, key, httpMethod, expiresIn);
    
    io:println(presignedURL);
}


isolated function createPresignedURL(string accessKeyId, string secretAccessKey, string region, string bucketName, string key, string httpMethod, int expiresIn) returns string|error {
    [string, string] [amzDateStr, shortDateStr] = ["", ""];
    var result = generateDateString();
    if (result is [string, string]) {
        [amzDateStr, shortDateStr] = result;
    } else {
        io:println("Error occurred while generating date string");
        return "";
    }

    string canonicalURI = "/" + key;

    string canonicalQueryString = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED_PAYLOAD&X-Amz-Credential=" + accessKeyId + "%2F" + shortDateStr
    + "%2F" + region + "%2F" + SERVICE_NAME + "%2F" + TERMINATION_STRING + "&X-Amz-Date=" + amzDateStr
    + "&X-Amz-Expires=" + expiresIn.toString() + "&X-Amz-SignedHeaders=host";

    string canonicalHeaders = "host:" + bucketName + "." + AMAZON_AWS_HOST;
    string signedHeaders = "host";


    string canonicalRequest = string `${httpMethod}${"\n"}${canonicalURI}${"\n"}${canonicalQueryString}${"\n"}${canonicalHeaders}${"\n"}${"\n"}${signedHeaders}${"\n"}${UNSIGNED_PAYLOAD}`;
    io:println(canonicalRequest);
  
    // Generate the string to sign
    string stringToSign = generateStringToSign(amzDateStr, shortDateStr, region, canonicalRequest);

    // Generate the signing key
    string signValue = AWS4 + secretAccessKey;
    byte[] dateKey = check crypto:hmacSha256(shortDateStr.toBytes(), signValue.toBytes());
    byte[] regionKey = check crypto:hmacSha256(region.toBytes(), dateKey);
    byte[] serviceKey = check crypto:hmacSha256(SERVICE_NAME.toBytes(), regionKey);
    byte[] signingKey = check crypto:hmacSha256(TERMINATION_STRING.toBytes(), serviceKey);
    string encodedStr = array:toBase16(check crypto:hmacSha256(stringToSign.toBytes(), signingKey));
    string signature = encodedStr.toLowerAscii();

    io:println(signature);

    string url = HTTPS + bucketName + "." + AMAZON_AWS_HOST + "/" + key + "?" + canonicalQueryString + "&X-Amz-Signature=" + signature;
    return url;
}

isolated function generateDateString() returns [string, string]|error {
    time:Utc time = time:utcNow();
    string amzDate = check utcToString(time, ISO8601_BASIC_DATE_FORMAT);
    string shortDate = check utcToString(time, SHORT_DATE_FORMAT);
    return [amzDate, shortDate];
}

isolated function utcToString(time:Utc utc, string pattern) returns string|error {
    [int, decimal] [epochSeconds, lastSecondFraction] = utc;
    int nanoAdjustments = (<int>lastSecondFraction * 1000000000);
    var instant = ofEpochSecond(epochSeconds, nanoAdjustments);
    var zoneId = getZoneId(java:fromString("Z"));
    var zonedDateTime = atZone(instant, zoneId);
    var dateTimeFormatter = ofPattern(java:fromString(pattern));
    handle formatString = format(zonedDateTime, dateTimeFormatter);
    return formatString.toBalString();
}

isolated function generateStringToSign(string amzDateStr, string shortDateStr, string region, string canonicalRequest)
                            returns string {
    //Start creating the string to sign
    string stringToSign = string `${AWS4_HMAC_SHA256}${"\n"}${amzDateStr}${"\n"}${shortDateStr}/${region}/${SERVICE_NAME}/${TERMINATION_STRING}${"\n"}${array:toBase16(crypto:hashSha256(canonicalRequest.toBytes())).toLowerAscii()}`;
    return stringToSign;

}

isolated function generateCanonicalQueryString(map<string> queryParams) returns string|error {
    string canonicalQueryString = "";
    string key;
    string value;
    string encodedKeyValue = EMPTY_STRING;
    string encodedValue = EMPTY_STRING;
    string[] queryParamsKeys = queryParams.keys();
    string[] sortedKeys = sort(queryParamsKeys);
    int index = 0;
    while (index < sortedKeys.length()) {
        key = sortedKeys[index];
        string encodedKey = check url:encode(key, UTF_8);
        encodedKeyValue = regex:replaceAll(encodedKey, ENCODED_SLASH, SLASH);
        value = <string>queryParams[key];
        string encodedVal = check url:encode(value, UTF_8);
        encodedValue = regex:replaceAll(encodedVal, ENCODED_SLASH, SLASH);
        canonicalQueryString = string `${canonicalQueryString}${encodedKeyValue}=${encodedValue}&`;
        index = index + 1;
    }
    canonicalQueryString = canonicalQueryString.substring(0, <int>string:lastIndexOf(canonicalQueryString, "&"));
    return canonicalQueryString;
}
