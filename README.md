## auditproxy
Trace and Audit HTTP calls

### Usage
Trace all HTTP calls to `backend-host`

```
./auditproxy -backend-host play.min.io:9000
```

```
~ mc alias set audit http://localhost:8443 <access_key> <secret_key> --api s3v4
~ mc ls audit/testbucket/
[2021-02-25 12:04:27 PST]  1KiB hosts
[2021-02-26 10:19:26 PST]  2KiB issue
```

You will see something like this on the `auditproxy` on standard output.
```
---------------------------
REQUEST GET /testbucket/?delimiter=%2F&encoding-type=url&fetch-owner=true&list-type=2&prefix= HTTP/1.1
Host: localhost:8443
Authorization: AWS4-HMAC-SHA256 Credential=minio/20210227/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a02f0905a6f8136e8b0ba90911edb1e5643c0caa08e83bc89fb3566842f574ec
User-Agent: MinIO (linux; amd64) minio-go/v7.0.9 mc/DEVELOPMENT.2021-02-16T18-14-29Z
X-Amz-Content-Sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20210227T020813Z



---------------------------
RESPONSE STATUS: 200 OK
Accept-Ranges: bytes
Content-Length: 962
Content-Security-Policy: block-all-mixed-content
Content-Type: application/xml
Date: Sat, 27 Feb 2021 02:08:13 GMT
Server: MinIO
Vary: Origin
X-Amz-Request-Id: 166778B12DF26493
X-Xss-Protection: 1; mode=block


--------------------------
```
