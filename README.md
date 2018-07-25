# ObjectStorage

This is a library for working with object storage services, like Amazon AWS S3, Digital Ocean Spaces, or Minio. It is written in C and conforms to the ANSI C99 standard for maximum compatability. It uses libCurl to handle making the HTTP requests and libCrypto from OpenSSL to handle the Sha256 hashing.

## Usage

`example.c` contains a complete example of how to use the library, and `buildExample.sh` shows how to link in libCurl and libCrypto. The accessID and secret key are just to a test instance of Minio (https://minio.io/), and will have to be changed to your own accessID and secret key.  

### Types

    struct ObjectStore {
        const char* host; 
        const char* secretKey;
        const char* accessID;
        const char* region;
        const char* bucketName;
    };
    
  ObjectStore is used to store all the information needed to connect to a particular bucket on a particular service.
  
  For example, to initialize an ObjectStore for a bucket named "test" on S3 in the us-east-1 region:
  
        struct ObjectStore myStore;
        myStore.host = "s3.amazonaws.com";
        myStore.secretKey = "AWS4WhaterYourSecretKeyIs";
        myStore.accessID = "WhateverYourAccessIDIs";
        myStore.region = "us-east-1";
        myStore.bucketName = "test";
        
   Note that the secret key must start with "AWS4", if your service does not show that, go ahead and add it.    
  
### Functions
   The `curl` argument to each of these functions if used to make the HTTP request and can be left as `NULL`. For better performance though, an initialized instance should be passed in. 
   
---   
#### Get An Object
    char* getObjectFromBucket(struct ObjectStore store, const char* objName, int* resultLen, CURL* curl, enum ObjectStoreResult* result);
   This function fetches the object with the name in `objName` from the given `store` and sets the length of the fetched data to `resultLen` and returns a pointer to the data. The status code is set to `result` and is `OBJ_STORE_OK` on success, `OBJ_STORE_NOT_FOUND` if the object does not exist, and OBJ_STORE_ERROR if some other error occurred. 
   
---
#### Upload Object
    enum ObjectStoreResult uploadObjectToBucket(struct ObjectStore store, const char* data, int dataLen, const char* objName, CURL* curl);
   This function uploads an object with the name in `objName` and contents stored in `data` with the length `dataLen` to the location specified by `store`. Returns `OBJ_STORE_OK` on success, and `OBJ_STORE_ERROR` on failure.
   
---   
#### Upload File
        enum ObjectStoreResult uploadFileToBucket(struct ObjectStore store, const char* file, CURL* curl);
   Similar to uploading an object, but instead of passing in data, pass in a file path. The file at `file` is read and uploaded with the same file name. Returns `OBJ_STORE_OK` on success, and `OBJ_STORE_ERROR` on failure.
   
---
#### Check If Object Exists
    enum ObjectStoreResult doesObjectExistInBucket(struct ObjectStore store, const char* objName, CURL* curl);
   This function checks if there is an object in the given `store` with the name in `objName`. Returns `OBJ_STORE_EXISTS` if found, `OBJ_STORE_NOT_FOUND` if not, and `OBJ_STORE_ERROR` if some error occurred.
   
---
#### Delete An Object
    enum ObjectStoreResult deleteObjectFromBucket(struct ObjectStore store, const char* objName, CURL* curl);
   This function deletes an object with the name in `objName` from the given `store`. Returns `OBJ_STORE_OK` on success, `OBJ_STORE_NOT_FOUND` if the object does not exist, and `OBJ_STORE_ERROR` if some other error occurred.
   
---


