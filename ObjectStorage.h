#pragma once
#include <curl/curl.h>

enum ObjectStoreResult {
    OBJ_STORE_OK,
    OBJ_STORE_ERROR,
    OBJ_STORE_EXISTS,
    OBJ_STORE_NOT_FOUND
};

struct ObjectStore {
    const char* host; 
    const char* secretKey;
    const char* accessID;
    const char* region;
    const char* bucketName;
};

enum ObjectStoreResult uploadObjectToBucket(struct ObjectStore store, const char* data, int dataLen, const char* objName, CURL* curl);
enum ObjectStoreResult uploadFileToBucket(struct ObjectStore store, const char* file, CURL* curl);
enum ObjectStoreResult doesObjectExistInBucket(struct ObjectStore store, const char* objName, CURL* curl);
enum ObjectStoreResult deleteObjectFromBucket(struct ObjectStore store, const char* objName, CURL* curl);
char* getObjectFromBucket(struct ObjectStore store, const char* objName, int* resultLen, CURL* curl, enum ObjectStoreResult* result);