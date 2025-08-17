
import base64
import hashlib
import hmac
import json
import os
import time
import logging
import boto3
import requests
from jose import jwt
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# === Secret Manager ===
def get_secrets():
    secrets_arn = os.environ.get("SECRET_ARN")
    if not secrets_arn:
        raise Exception("Missing SECRET_ARN env variable")

    sm = boto3.client("secretsmanager")
    try:
        resp = sm.get_secret_value(SecretId=secrets_arn)
        secret_data = resp.get("SecretString")
        if not secret_data:
            raise Exception("Empty secret")
        return json.loads(secret_data)
    except ClientError as e:
        logger.error(f"Failed to get secrets: {e}")
        raise

# === Load secrets ===
secrets = get_secrets()
APP_ID = secrets["GITHUB_APP_ID"]
BOT_LOGIN = secrets["BOT_LOGIN"]
key_raw = secrets["GITHUB_APP_PRIVATE_KEY"]
PRIVATE_KEY_PEM = key_raw.replace("\\n", "\n") if "\\n" in key_raw else key_raw
WEBHOOK_SECRET = secrets["GITHUB_WEBHOOK_SECRET"].encode()
OPENAI_API_KEY = secrets.get("OPENAI_API_KEY")

# === Helpers ===
def alb_resp(status, body, content_type="application/json"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    return {
        "statusCode": status,
        "statusDescription": f"{status} OK" if 200 <= status < 300 else f"{status}",
        "isBase64Encoded": False,
        "headers": {"content-type": content_type},
        "body": body,
    }

def verify_signature(headers, body_bytes):
    sig = headers.get("x-hub-signature-256")
    if not sig or not sig.startswith("sha256="):
        return False
    digest = hmac.new(WEBHOOK_SECRET, body_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, f"sha256={digest}")

def _app_jwt():
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 540, "iss": APP_ID}
    return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")

def _inst_token(installation_id):
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {_app_jwt()}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "dev-review-lambda",
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]

def _safe_get(d, path, default=None):
    for key in path:
        if not isinstance(d, dict) or key not in d:
            return default
        d = d[key]
    return d

def _should_trigger(payload):
    return _safe_get(payload, ["requested_reviewer", "login"]) == BOT_LOGIN

def _load_rules():
    try:
        with open("rules.json", "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load rules.json: {e}")
        return []

def _get_tf_code_from_pr(files):
    tf_code = ""
    for file in files:
        if file["filename"].endswith(".tf"):
            raw_url = file.get("raw_url")
            if raw_url:
                r = requests.get(raw_url)
                if r.status_code == 200:
                    tf_code += f"\n# File: {file['filename']}\n" + r.text
    return tf_code if tf_code.strip() else None

def _post_inline_comment(owner, repo, pr_number, installation_id, payload):
    try:
        from langchain_community.chat_models import BedrockChat
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
    except ImportError as e:
        logger.error(f"Langchain import failed: {e}")
        raise

    token = _inst_token(installation_id)
    logger.info("Fetched GitHub token")

    files_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
    r_files = requests.get(files_url, headers={"Authorization": f"Bearer {token}"})
    r_files.raise_for_status()
    files = r_files.json()

    tf_code = _get_tf_code_from_pr(files)
    if not tf_code:
        logger.warning("No .tf files found in PR.")
        return

    rules = _load_rules()
    logger.info(f"Loaded rules: {json.dumps(rules, indent=2)}")
    logger.info(f"Loaded Terraform code:\n{tf_code}")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an expert in IaC security and Terraform code review."),
        ("human", """
Here are security rules:

```json
{rules}
```

Here is the Terraform code:

```hcl
{tf_code}
```

Please analyze and provide concise review comments based on these rules.
""")
    ])

    llm = BedrockChat(
        model_id="anthropic.claude-3-5-haiku-20241022-v1:0",
        model_kwargs={"max_tokens": 1000, "temperature": 0.3}
    )

    chain = prompt | llm | StrOutputParser()
    inputs = {
        "rules": json.dumps(rules, indent=2),
        "tf_code": tf_code
    }
    logger.info(f"Sending to model: {json.dumps(inputs, indent=2)}")

    comment_text = chain.invoke(inputs)
    logger.info(f"Generated review comment: {comment_text}")

    commit_id = _safe_get(payload, ["pull_request", "head", "sha"])

    valid_line = None
    for f in files:
        if f["filename"].endswith(".tf"):
            patch = f.get("patch", "")
            for i, line in enumerate(patch.splitlines(), 1):
                if line.startswith("+") and not line.startswith("+++"):
                    valid_line = f["filename"], commit_id, i
                    break
            if valid_line:
                break

    if not valid_line:
        logger.warning("No valid line found in diff to comment on.")
        return

    path, commit_id, line = valid_line
    comment_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    r = requests.post(
        comment_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "body": comment_text,
            "commit_id": commit_id,
            "path": path,
            "line": line,
            "side": "RIGHT"
        },
    )
    r.raise_for_status()
    logger.info("Posted inline comment")

# === Entry ===
def lambda_handler(event, context):
    is_b64 = event.get("isBase64Encoded", False)
    body_raw = event.get("body") or ""
    body_bytes = base64.b64decode(body_raw) if is_b64 else body_raw.encode("utf-8")

    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    if not verify_signature(headers, body_bytes):
        logger.warning("Invalid signature")
        return alb_resp(401, {"ok": False, "error": "invalid signature"})

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return alb_resp(400, {"ok": False, "error": "invalid json"})

    event_type = headers.get("x-github-event", "")
    logger.info(f"Received GitHub event: {event_type}")

    if event_type == "ping":
        return alb_resp(200, "pong", content_type="text/plain")

    if event_type == "pull_request":
        action = payload.get("action")
        pr_number = _safe_get(payload, ["pull_request", "number"])
        branch = _safe_get(payload, ["pull_request", "head", "ref"])
        owner = _safe_get(payload, ["repository", "owner", "login"])
        repo = _safe_get(payload, ["repository", "name"])
        installation_id = _safe_get(payload, ["installation", "id"])

        logger.info(f"PR #{pr_number} on branch {branch} ({action})")

        if action == "opened":
            logger.info("PR opened, but no reviewer selected")
            return alb_resp(200, {"ok": True, "triggered": False, "reason": "no reviewer yet"})

        if action == "review_requested" and _should_trigger(payload):
            try:
                _post_inline_comment(owner, repo, pr_number, installation_id, payload)
                return alb_resp(200, {"ok": True, "triggered": True})
            except Exception as e:
                logger.exception("Review failed")
                return alb_resp(200, {"ok": False, "error": str(e)})

    return alb_resp(200, {"ok": True, "reason": "ignored event"})
