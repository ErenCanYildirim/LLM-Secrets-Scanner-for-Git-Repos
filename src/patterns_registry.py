from typing import List
from data_classes import ScanPattern


class PatternRegistry:
    """
    A registry for secret detection patterns used in regex-based scanning.

    Holds a list of ScanPattern objects with RegEx, keywords and metadata for identifying common secrets.

    Add further ScanPatterns as desired.
    """

    def __init__(self):
        self.patterns = self._load_default_patterns()

    def _load_default_patterns(self) -> List[ScanPattern]:
        """
        Loads a list of default ScanPatterns.

        NOTE: For proper coding practices, this list might get too large eventually, so perhaps reading it in via a file or even a database might
              be the preferred approach.
        """

        return [
            ScanPattern(
                name="aws_access_key",
                regex=r"AKIA[0-9A-Z]{16}",
                keywords=["aws", "access", "key", "akia"],
                description="AWS Access Key ID",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="aws_secret_key",
                regex=r'(?i)aws(.{0,20})?["\']?[0-9a-zA-Z/+=]{40}["\']?',
                keywords=["aws", "secret", "key"],
                description="AWS Secret Access Key",
                confidence_boost=0.2,
            ),
            ScanPattern(
                name="api_key_generic",
                regex=r'(?i)(api[_\-\s]?key|apikey)[\s]*[:=][\s]*["\']?[a-zA-Z0-9\-_]{20,}["\']?',
                keywords=["api", "key", "token", "bearer"],
                description="Generic API Key",
                confidence_boost=0.1,
            ),
            ScanPattern(
                name="github_token",
                regex=r"gh[ps]_[A-Za-z0-9]{36}",
                keywords=["github", "token", "gh_", "ghs_", "ghp_"],
                description="GitHub Personal Access Token",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="private_key",
                regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY",
                keywords=["private", "key", "rsa", "pem", "ssh"],
                description="Private Cryptographic Key",
                confidence_boost=0.5,
            ),
            ScanPattern(
                name="password",
                regex=r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*["\']?[^\s"\'{}<>]{8,}["\']?',
                keywords=["password", "passwd", "pwd", "pass"],
                description="Hardcoded Password",
                confidence_boost=0.1,
            ),
            ScanPattern(
                name="db_connection",
                regex=r'(?i)(mongodb\+srv|postgres|mysql|redis|amqp|jdbc):\/\/[^\s<>"{}\\^\[\]`]+',
                keywords=[
                    "connection",
                    "database",
                    "mongodb",
                    "postgres",
                    "mysql",
                    "redis",
                ],
                description="Database Connection String",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="jwt_token",
                regex=r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
                keywords=["jwt", "token", "bearer", "authorization"],
                description="JWT Token",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="slack_token",
                regex=r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}",
                keywords=["slack", "token", "xoxb", "xoxp"],
                description="Slack Token",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="google_api",
                regex=r"AIza[0-9A-Za-z\-_]{35}",
                keywords=["google", "api", "key", "aiza"],
                description="Google API Key",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="stripe_key",
                regex=r"sk_live_[0-9a-zA-Z]{24}",
                keywords=["stripe", "secret", "key", "sk_live"],
                description="Stripe Secret Key (Live)",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="azure_connection",
                regex=r'(?i)azure(.{0,20})?["\']?[A-Za-z0-9+/=]{50,}["\']?',
                keywords=["azure", "connection", "storage", "account", "key"],
                description="Azure Storage Account Key or Connection String",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="facebook_access_token",
                regex=r"EAACEdEos0BA[ A-Za-z0-9]{50,}",
                keywords=["facebook", "access", "token", "eaac"],
                description="Facebook Access Token",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="twitter_api_key",
                regex=r'(?i)twitter(.{0,20})?["\']?[A-Za-z0-9]{25,}["\']?',
                keywords=["twitter", "api", "key", "secret", "bearer"],
                description="Twitter API Key or Secret",
                confidence_boost=0.2,
            ),
            ScanPattern(
                name="ssh_private_key_id_rsa",
                regex=r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----",
                keywords=["ssh", "id_rsa", "private", "key"],
                description="Full SSH Private Key Block (RSA)",
                confidence_boost=0.5,
            ),
            ScanPattern(
                name="npm_token",
                regex=r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                keywords=["npm", "token", "auth"],
                description="NPM Authentication Token (UUID format)",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="docker_hub_token",
                regex=r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]{50,}",
                keywords=["docker", "hub", "token", "jwt"],
                description="Docker Hub JWT Token (longer signature variant)",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="sendgrid_api_key",
                regex=r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
                keywords=["sendgrid", "api", "key", "sg."],
                description="SendGrid API Key",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="mailchimp_api_key",
                regex=r"[0-9a-f]{32}-us[0-9]{1,2}",
                keywords=["mailchimp", "api", "key"],
                description="Mailchimp API Key",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="pypi_token",
                regex=r"pypi-[A-Za-z0-9\-_]{30,}",
                keywords=["pypi", "token", "upload"],
                description="PyPI Upload Token",
                confidence_boost=0.4,
            ),
            ScanPattern(
                name="openssl_private_key",
                regex=r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
                keywords=["openssl", "private", "key", "openssh"],
                description="OpenSSH Private Key Block",
                confidence_boost=0.5,
            ),
            ScanPattern(
                name="cloudinary_creds",
                regex=r"cloudinary://[0-9]{15,}:[A-Za-z0-9_]{20,}@[a-zA-Z0-9-]+",
                keywords=["cloudinary", "api", "key", "secret"],
                description="Cloudinary API Key and Secret in URL",
                confidence_boost=0.3,
            ),
            ScanPattern(
                name="s3_bucket_url",
                regex=r"(?i)s3://[a-z0-9.-]+\.amazonaws\.com/[a-zA-Z0-9/_\-]{20,}",
                keywords=["s3", "bucket", "aws", "amazon"],
                description="AWS S3 Bucket URL with Potential Path Secrets",
                confidence_boost=0.2,
            ),
        ]

    def add_pattern(self, pattern: ScanPattern):
        if not isinstance(pattern, ScanPattern):
            raise TypeError("Pattern must be a ScanPattern instance.")
        self.patterns.append(pattern)

    def get_pattern(self) -> List[ScanPattern]:
        return self.patterns
