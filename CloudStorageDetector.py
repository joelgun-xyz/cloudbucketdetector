from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpRequestResponse
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Cloud Storage Detector")
        callbacks.registerScannerCheck(self)

        self._stdout = callbacks.getStdout()
        self._stdout.write("Cloud Storage Detector extension loaded.\n")

        # Regex patterns for cloud storage URLs
        self.s3_regex = re.compile(
            r'https?://(?:[a-z0-9\-\.]+\.s3(?:-[a-z0-9\-]+)?\.amazonaws\.com|s3(?:-[a-z0-9\-]+)?\.amazonaws\.com/[a-z0-9\-\.]+)',
            re.IGNORECASE
        )

        self.gcp_regex = re.compile(
            r'https?://storage\.googleapis\.com/[a-z0-9._\-]+|https?://[a-z0-9._\-]+\.storage\.googleapis\.com',
            re.IGNORECASE
        )

        self.azure_regex = re.compile(
            r'https?://[a-z0-9\-]{3,24}\.blob\.core\.windows\.net(/[^\s"\']*)?',
            re.IGNORECASE
        )

    def doPassiveScan(self, baseRequestResponse):
        url = baseRequestResponse.getUrl().toString()
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()

        # Combine all relevant data to scan
        all_data = url

        if request:
            analyzed_req = self._helpers.analyzeRequest(baseRequestResponse)
            body_offset = analyzed_req.getBodyOffset()
            body = self._helpers.bytesToString(request)[body_offset:]
            headers = "\n".join(analyzed_req.getHeaders())
            all_data += "\n" + headers + "\n" + body

        if response:
            analyzed_resp = self._helpers.analyzeResponse(response)
            body_offset = analyzed_resp.getBodyOffset()
            body = self._helpers.bytesToString(response)[body_offset:]
            headers = "\n".join(analyzed_resp.getHeaders())
            all_data += "\n" + headers + "\n" + body

        issues = []

        # Find S3 URLs
        s3_matches = list(set(self.s3_regex.findall(all_data)))
        if s3_matches:
            self._stdout.write("[+] AWS S3 bucket(s) detected in: " + url + "\n")
            for b in s3_matches:
                self._stdout.write("  - " + b + "\n")
            issues.append(CloudStorageIssue(baseRequestResponse, s3_matches, "AWS S3", self._callbacks, self._helpers))

        # Find GCP URLs
        gcp_matches = list(set(self.gcp_regex.findall(all_data)))
        if gcp_matches:
            self._stdout.write("[+] GCP bucket(s) detected in: " + url + "\n")
            for b in gcp_matches:
                self._stdout.write("  - " + b + "\n")
            issues.append(CloudStorageIssue(baseRequestResponse, gcp_matches, "GCP Storage", self._callbacks, self._helpers))

        # Find Azure URLs
        azure_matches = list(set(self.azure_regex.findall(all_data)))
        if azure_matches:
            self._stdout.write("[+] Azure blob(s) detected in: " + url + "\n")
            for b in azure_matches:
                self._stdout.write("  - " + b + "\n")
            issues.append(CloudStorageIssue(baseRequestResponse, azure_matches, "Azure Blob Storage", self._callbacks, self._helpers))

        return issues if issues else None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # No active scan implemented
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # Merge duplicates if issue names match
        return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0


class CloudStorageIssue(IScanIssue):
    def __init__(self, baseRequestResponse, matches, service_type, callbacks, helpers):
        self._baseRequestResponse = baseRequestResponse
        self._matches = matches
        self._service_type = service_type
        self._callbacks = callbacks
        self._helpers = helpers
        self._unauthenticated = False

        # Check unauthenticated access by sending simple GET requests
        self._check_unauthenticated_access()

    def _check_unauthenticated_access(self):
        for url in self._matches:
            try:
                # Build a request for the URL
                httpService = self._baseRequestResponse.getHttpService()
                # Parse the URL string to URL object via Burp helper
                url_obj = self._helpers.analyzeRequest(self._baseRequestResponse).getUrl()
                
                # Build a new HTTP request for this URL
                new_request = self._helpers.buildHttpRequest(self._helpers.stringToBytes(url))
                
                # Send the request (follow redirects false, do not use a new thread)
                resp = self._callbacks.makeHttpRequest(httpService, new_request)
                if resp:
                    resp_info = self._helpers.analyzeResponse(resp.getResponse())
                    status_code = resp_info.getStatusCode()
                    # Basic unauthenticated check: HTTP 200 or 403 (bucket exists but no perms)
                    if status_code in [200, 403]:
                        self._unauthenticated = True
                        break
            except Exception:
                pass

    def getUrl(self): return self._baseRequestResponse.getUrl()
    def getIssueName(self): return "{} Bucket Detected".format(self._service_type)
    def getIssueType(self): return 0x08000000  # Info disclosure
    def getSeverity(self): return "Low" if not self._unauthenticated else "Medium"
    def getConfidence(self): return "Certain"

    def getIssueBackground(self):
        return ("This issue identifies potentially exposed {} URLs observed in HTTP traffic. "
                "If these resources are publicly accessible, they may leak sensitive data.").format(self._service_type)

    def getRemediationBackground(self):
        return ("Ensure {} access permissions are properly configured. "
                "Avoid public exposure unless necessary.").format(self._service_type)

    def getIssueDetail(self):
        unauth_text = ""
        if self._unauthenticated:
            unauth_text = "<b>Unauthenticated access appears possible for at least one bucket.</b><br><br>"

        return (unauth_text +
                "Detected the following {} references:<br><br>".format(self._service_type) +
                "<br>".join(self._matches))

    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._baseRequestResponse]
    def getHttpService(self): return self._baseRequestResponse.getHttpService()
