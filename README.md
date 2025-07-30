# Cloud Storage Detector — Burp Suite Extension

**Cloud Storage Detector** is a Burp Suite extension designed to passively identify exposed cloud storage buckets in HTTP traffic. It supports detecting URLs for:

- **AWS S3 Buckets**
- **Google Cloud Platform (GCP) Storage Buckets**
- **Microsoft Azure Blob Storage**

Additionally, the extension performs basic unauthenticated access checks by issuing simple HTTP GET requests to detected bucket URLs and flags buckets that appear publicly accessible.

---

## Features

- **Passive scanning** for cloud storage URLs in requests and responses
- Detection of **AWS S3**, **GCP Storage**, and **Azure Blob Storage** URLs using regex patterns
- Basic **unauthenticated access check** to determine if buckets are publicly reachable (checks for HTTP 200 or 403)
- Reports findings as Burp issues with appropriate severity:
  - *Low* for detected buckets
  - *Medium* if unauthenticated access appears possible
- Consolidates duplicate issues

---

## Installation

1. Open Burp Suite and navigate to **Extender > Extensions**.
2. Click **Add** and select **Python** as the extension type.
3. Load the `CloudStorageDetector.py` file.
4. The extension will load and start passively scanning traffic.

---

## Usage

- Intercept or browse web traffic as usual.
- The extension will automatically detect cloud storage URLs in HTTP requests and responses.
- Issues will be reported in the **Scanner** tab with details about the exposed buckets and access level.
- Review issues to verify and take remediation actions as needed.

---

## Example Detected URLs

- **AWS S3**:  
  `https://mybucket.s3.amazonaws.com/path/to/object`  
  `https://s3-us-west-1.amazonaws.com/mybucket`

- **GCP Storage**:  
  `https://storage.googleapis.com/my-bucket/object`  
  `https://my-bucket.storage.googleapis.com/object`

- **Azure Blob Storage**:  
  `https://myaccount.blob.core.windows.net/container/blob.txt`  
  `https://azureopendatastorage.blob.core.windows.net/nyctaxi/2019-trip-data/green_tripdata_2019-01.csv`

---

## Limitations

- The unauthenticated access check is a simple GET request and may not detect all access restrictions or bucket policies.
- Active scanning functionality is not implemented.

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to submit pull requests or open issues for improvements.

---

## License

This project is licensed under the MIT License.

