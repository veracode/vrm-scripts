import requests, os, time, uuid
import hmac
import hashlib
from urllib.parse import urlparse

# === Inputs ===
API_ID = os.environ.get('APIID')
API_KEY = os.environ.get('APIKEY')
REQUEST_VERSION = "vcode_request_version_1"


########################## BEGIN HMAC AUTH FUNCTIONS ##########################

def hmac_sha256_hex(key_hex: str, message: str) -> str:
    key_bytes = bytes.fromhex(key_hex)
    return hmac.new(key_bytes, message.encode("utf-8"), hashlib.sha256).hexdigest()

def calculate_signature(api_key, nonce, ts, data):
    k_nonce = hmac_sha256_hex(api_key, nonce)
    k_date = hmac_sha256_hex(k_nonce, ts)
    k_sig = hmac_sha256_hex(k_date, REQUEST_VERSION)
    return hmac_sha256_hex(k_sig, data)

def generate_auth_header(api_id, api_key, method, url):
    parsed = urlparse(url)
    url_path = parsed.path
    if parsed.query:
        url_path += "?" + parsed.query

    ts = str(int(time.time() * 1000))
    nonce = uuid.uuid4().hex.upper()
    nonce_hex = nonce.encode("utf-8").hex().upper()

    data = f"id={api_id}&host={parsed.hostname}&url={url_path}&method={method.upper()}"
    sig = calculate_signature(api_key, nonce, ts, data)

    return f"VERACODE-HMAC-SHA-256 id={api_id},ts={ts},nonce={nonce_hex},sig={sig}"

########################## END HMAC AUTH FUNCTIONS ##########################


# API call to list all integrations
def get_integrations(base_url, tenant):
    url = f"https://{base_url}/v1/graphql"

    payload = "{\"query\":\"query ListIntegrations($filter: IntegrationFilter, $sortCriteria: IntegrationSortCriteria) {\\n  listIntegrations(filter: $filter, sortCriteria: $sortCriteria) {\\n    id\\n    name\\n    state\\n    cloudServiceProvider\\n    accountId\\n    accountValue\\n    updatedAt\\n    createdAt\\n    issueCount\\n    isUConnect\\n    connectionInfo {\\n      status\\n      lastCheckedAt\\n      lastSuccessfullyConnectedAt\\n    }\\n    regions\\n    ingestionInfo {\\n      lastIngestionAt\\n      lastSuccessfulIngestionAt\\n      lastFailureIngestionAt\\n      lastSuccessfulJobExecutionId\\n    }\\n    analysisInfo {\\n      lastSuccessfulJobId\\n      lastSuccessfulJobExecutionId\\n      lastSuccessfulAnalysisRunAt\\n    }\\n    defaultScheduledJob {\\n      status\\n      nextRunTime\\n    }\\n  }\\n}\",\"variables\":{\"sortCriteria\":{\"sortField\":\"lastConnectedAt\",\"sortOrder\":\"DESC\"}}}"
    headers = {
    'x-alta-tenant': tenant,
    'Authorization': generate_auth_header(API_ID, API_KEY, "POST", url),
    'Content-Type': 'application/json'
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        return None
    
    all_integrations = response.json()["data"]["listIntegrations"]

    return all_integrations


if __name__ == "__main__":
    tenant_id = os.environ.get('XALTATENANT')
    base_url = "api.veracode.com/risk-manager/api-server"

    all_integrations = get_integrations(base_url, tenant_id)
    print(all_integrations)