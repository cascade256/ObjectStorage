#include "ObjectStorage.h"
#include <curl/curl.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

const char* AUTH_HEADER_FORMAT_STR = "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s";
const char* EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

char* makeRequest(struct ObjectStore store, const char* method, const char* objName, const char* data, int dataLen, int* resultLen, CURL* curl, enum ObjectStoreResult* result);

#ifdef OBJECT_STORAGE_ENABLE_LOGGING
    #define logError(x) printf(x)
#else
    #define logError(x)
#endif

struct StreamWriteBuffer {
    char* data;
    int len;
};

size_t writeToStreamBuffer(void* ptr, size_t size, size_t nmemb, struct StreamWriteBuffer* buffer) {
    if(buffer->data == NULL) {
        buffer->data = (char*)malloc(size * nmemb + 1);//An extra byte for a terminating null byte
        memcpy(buffer->data, ptr, size * nmemb);
        buffer->len = size * nmemb;
        buffer->data[buffer->len] = 0;
    }
    else {
        char* newData = (char*)malloc(size * nmemb + buffer->len + 1);
        memcpy(newData, buffer->data, buffer->len);
        memcpy(&newData[buffer->len], ptr, size * nmemb);
        buffer->len += size * nmemb;
        newData[buffer->len] = 0;

        free(buffer->data);
        buffer->data = newData;
    }

    return size * nmemb;
}

struct StreamReadBuffer{
    const char* data;
    int offset;
    int len;
};

size_t readFromStreamBuffer(char* buffer, size_t size, size_t nitems, struct StreamReadBuffer* data) {
    if(data->len <= data->offset) {
        assert(data->len >= data->offset);
        return 0;
    }
    else if(size * nitems > (size_t)(data->len - data->offset)) {
        int bytesRead = data->len - data->offset;
        memcpy(buffer, &data->data[data->offset], bytesRead);
        data->offset = data->len;
        return bytesRead;
    }
    else {
        int bytesRead = size * nitems;
        memcpy(buffer, &data->data[data->offset], bytesRead);
        data->offset += bytesRead;
        return bytesRead;
    }
}

char numToHex(int num) {
    if(num < 10) {
        return '0' + num;
    }
    else if(num < 16) {
        return 'a' + num - 10;
    }
    else {
        assert(false);
    }
}

void hexEncode(char* data, int dataLen, char* hexBuffer) {
    for(int i = 0; i < dataLen; i++) {
        hexBuffer[i * 2 + 0] = numToHex(((unsigned char)data[i]) >> 4);
        hexBuffer[i * 2 + 1] = numToHex(((unsigned char)data[i]) & 0xF);
    }
    hexBuffer[dataLen * 2] = 0;
}

void hmac(char* buffer, const char* key, int keyLen, const char* str) {
    buffer[32] = 0;
    int len;
    HMAC(EVP_sha256(), key, keyLen, (unsigned char*)str, strlen(str), (unsigned char*)buffer, (unsigned int*)&len);
    assert(len == 32);
}

//Buffer must be at least 33 bytes
void sha256(char* buffer, const char* data, int dataLen) {
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, data, dataLen);
    SHA256_Final((unsigned char*)buffer, &sha);
}

//Buffer must be at least 17 bytes
void generateISO_8601_Time(char* buff) {
    time_t t;
    time(&t);
    struct tm* utc = gmtime(&t);
    snprintf(buff, 17, "%.4i%.2i%.2iT%.2i%.2i%.2iZ", utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday, utc->tm_hour, utc->tm_min, utc->tm_sec);
    //strcpy(buff, "20180312T110053Z");
}

//Buffer must be at least 9 bytes
void generateDate(char* buff) {
    time_t t;
    time(&t);
    struct tm* utc = gmtime(&t);
    snprintf(buff, 9, "%.4i%.2i%.2i", utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday);
    //strcpy(buff, "20180312");
}

char* generateStringToSign(const char* canonicalRequestHash, const char* region, const char* service) {
    const char* stringToSignFormatString = "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s";
    char* stringToSign = (char*)malloc(1024);
    char utcTime[17];
    generateISO_8601_Time(utcTime);
    //strcpy(utcTime, "20130524T000000Z");
    char date[9];
    generateDate(date);
    //strcpy(date, "20130524");
    snprintf(stringToSign, 1024, stringToSignFormatString, utcTime, date, region, service, canonicalRequestHash);
    return stringToSign;
}

void createAuthorizationHeader(char* buffer, int buffLen, struct ObjectStore store, char* canonicalRequest) {
    char date[9];
    generateDate(date);
    char hash[33];
    sha256(hash, canonicalRequest, strlen(canonicalRequest));
    char hexHash[65];
    hexEncode(hash, 32, hexHash);
    char* stringToSign = generateStringToSign(hexHash, store.region, "s3");
    //logI("String to sign:\n%s\n", stringToSign);

    //Step 3: Signing Key
    char signingKey[33];
    hmac(signingKey, store.secretKey, strlen(store.secretKey), date);
    //logI("dateKey: %s\n", hexEncode(signingKey, 32));
    hmac(signingKey, signingKey, 32, store.region);
    //logI("regionKey: %s\n", hexEncode(signingKey, 32));
    hmac(signingKey, signingKey, 32, "s3");
    //logI("serviceKey: %s\n", hexEncode(signingKey, 32));
    hmac(signingKey, signingKey, 32, "aws4_request");
    //logI("Signing Key: %s\n", hexEncode(signingKey, 32));

    //Step 4: Signature
    char signatureBuff[33];
    hmac(signatureBuff, signingKey, 32, stringToSign);
    char signature[65];
    hexEncode(signatureBuff, 32, signature);

    snprintf(buffer, buffLen, AUTH_HEADER_FORMAT_STR, store.accessID, date, store.region, "s3", signature);
    free(stringToSign);
}

enum ObjectStoreResult uploadFileToBucket(struct ObjectStore store, const char* file, CURL* curl) {
    char* fileData;
    int fileLen;
    {
        FILE* f = fopen(file, "rb");
        if(f == NULL) {
            logError("There was an error opening the file\n");
            return OBJ_STORE_ERROR;
        }

        fseek(f, 0, SEEK_END);
        fileLen = ftell(f);
        rewind(f);
        fileData = (char*)malloc(fileLen);
        fread(fileData, 1, fileLen, f);
        fclose(f);
    }
    
    return uploadObjectToBucket(store, fileData, fileLen, strrchr(file, '/'), curl);
}

enum ObjectStoreResult uploadObjectToBucket(struct ObjectStore store, const char* objData, int objDataLen, const char* objName, CURL* curl){
    enum ObjectStoreResult result;
    if(store.host == NULL) {
        char buff[1024];
        snprintf(buff, 1024, "%s/%s", store.bucketName, objName);
        FILE* file = fopen(buff, "wb");
        if(file == NULL) {
            return OBJ_STORE_ERROR;
        }
        fwrite(objData, sizeof(char), objDataLen, file);
        fclose(file);
        return OBJ_STORE_OK;
    }
    int responseLen;
    char* response = makeRequest(store, "PUT", objName, objData, objDataLen, &responseLen, curl, &result);
    if(response != NULL) {
        free(response);
    }
    
    return result;
}

enum ObjectStoreResult doesObjectExistInBucket(struct ObjectStore store, const char* objName, CURL* curl){
    if(store.host == NULL) {
        char buff[1024];
        snprintf(buff, 1024, "%s/%s", store.bucketName, objName);
        struct stat statBuff;
        if(stat(buff, &statBuff) == 0) {
            return OBJ_STORE_EXISTS;
        }
        else {
            return OBJ_STORE_NOT_FOUND;
        }
    }
    enum ObjectStoreResult result;
    char* response = makeRequest(store, "HEAD", objName, NULL, 0, NULL, curl, &result);
    if(response != NULL) {
        free(response);
    }
    
    if(result == OBJ_STORE_OK) {
        result = OBJ_STORE_EXISTS;
    }

    return result;
}

enum ObjectStoreResult deleteObjectFromBucket(struct ObjectStore store, const char* objName, CURL* curl) {
    enum ObjectStoreResult result;
    char* response = makeRequest(store, "DELETE", objName, NULL, 0, NULL, curl, &result);
    if(response != NULL) {
        free(response);
    }
    
    return result;
}

char* getObjectFromBucket(struct ObjectStore store, const char* objName, int* resultLen, CURL* curl, enum ObjectStoreResult* result){
    if(store.host == NULL) {
        char buff[1024];
        snprintf(buff, 1024, "%s/%s", store.bucketName, objName);
        FILE* file = fopen(buff, "rb");
        if(file == NULL) {
            *result = OBJ_STORE_NOT_FOUND;
            return NULL;
        }
        fseek(file, 0, SEEK_END);
        *resultLen = ftell(file);
        rewind(file);
        char* out = (char*)malloc(*resultLen);
        fwrite(out, 1, *resultLen, file);
        fclose(file);
        *result = OBJ_STORE_OK;
        return out;
    }
    char* response = makeRequest(store, "GET", objName, NULL, 0, resultLen, curl, result);
    return response;
}

char* makeRequest(struct ObjectStore store, const char* method, const char* objName, const char* data, int dataLen, int* resultLen, CURL* curl, enum ObjectStoreResult* result){
    //Create the file hash
    const char* fileHashHex;    
    if(data != NULL) {
        char fileHash[33];
        char fileHashHexBuffer[65];
        sha256(fileHash, data, dataLen);
        hexEncode(fileHash, 32, fileHashHexBuffer);
        fileHashHex = fileHashHexBuffer;
    }
    else {
        fileHashHex = EMPTY_HASH;
    }

    //Create the timestamp
    char utcTime[17];
    generateISO_8601_Time(utcTime);

    //Create the canonical request
    const char* requestFormatString = "%s\n/%s/%s\n\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\nhost;x-amz-content-sha256;x-amz-date\n%s";
    char canonicalRequest[1024];
    snprintf(canonicalRequest, 1024, requestFormatString, method, store.bucketName, objName, store.host, fileHashHex, utcTime, fileHashHex);

    //Create the authorization header from the canonical request
    char authHeader[1024];
    createAuthorizationHeader(authHeader, 1024, store, canonicalRequest);

    //Add headers
    char dateHeader[1024];
    snprintf(dateHeader, 1024, "x-amz-date: %s", utcTime);
    char contentHashHeader[1024];
    snprintf(contentHashHeader, 1024, "x-amz-content-sha256: %s", fileHashHex);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, authHeader);
    headers = curl_slist_append(headers, contentHashHeader);
    headers = curl_slist_append(headers, dateHeader);

    //Create the URL
    char url[1024];
    snprintf(url, 1024, "http://%s/%s/%s", store.host, store.bucketName, objName);

    //Make the request
    struct StreamWriteBuffer response;
    response.data = NULL;
    response.len = 0;

    bool cleanupCurl = false;
    if(curl == NULL) {
        curl = curl_easy_init();
        cleanupCurl = true;
    }

    CURLcode res;
    curl_easy_reset(curl);
    if(strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    }
    if(data != NULL) {
        struct StreamReadBuffer readData;
        readData.data = data;
        readData.offset = 0;
        readData.len = dataLen;
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readFromStreamBuffer);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readData);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, dataLen);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToStreamBuffer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    //Error handling
    if(res != CURLE_OK) {
        logError("There was an error making the CURL request\n");
        *result = OBJ_STORE_ERROR;
    }
    else {
        long code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        if(code == 200 || code == 204) {
            *result = OBJ_STORE_OK;
        }
        else if (code == 404){
            *result = OBJ_STORE_NOT_FOUND;
        }
        else {
            *result = OBJ_STORE_ERROR;
        }   
    }

    //Cleanup curl if we created it
    if(cleanupCurl) {
        curl_easy_cleanup(curl);
    }

    if(resultLen != NULL) {
        *resultLen = response.len;
    }
    
    return response.data;
}
