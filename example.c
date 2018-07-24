#include "ObjectStorage.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>

int main() {
    curl_global_init(CURL_GLOBAL_ALL);

    struct ObjectStore store;
    store.accessID = "H4Y4257ES1OP867UEI14";
    store.secretKey = "AWS4IdzpBkBEs7usd+Y0BgHAUNyvrykRQJx8T6ZsH5C2";
    store.host = "localhost:9000";
    store.bucketName = "test";
    store.region = "us-east-1";

    enum ObjectStoreResult result;
    
    const char* objData = "My object data";
    const char* objName = "MyObject";
    result = uploadObjectToBucket(store, objData, strlen(objData), objName, NULL);
    assert(result == OBJ_STORE_OK);

    result = doesObjectExistInBucket(store, objName, NULL);
    assert(result == OBJ_STORE_EXISTS);

    int downloadedObjLen;
    char* downloadedObj = getObjectFromBucket(store, objName, &downloadedObjLen, NULL, &result);
    assert(result == OBJ_STORE_OK);
    printf("MyObject: %s\n", downloadedObj);
    free(downloadedObj);

    result = deleteObjectFromBucket(store, objName, NULL);
    assert(result == OBJ_STORE_OK);

    result = doesObjectExistInBucket(store, objName, NULL);
    assert(result == OBJ_STORE_NOT_FOUND);

    curl_global_cleanup();
    return 0;
}