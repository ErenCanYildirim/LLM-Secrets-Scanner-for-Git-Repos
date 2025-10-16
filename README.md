# Git secrets scanner 

An LLM-powered CLI-tool that scans Git repositories for hardcoded secrets and sensitive information.

## Features
    - Combines RegEx patterns with LLM analysis
    - Checks last N commits by diffs including the commit messages
    - Checks uncommitted changes (staged, unstaged and untracked files)
    - Supports local and remote Git repositories
    - In-Memory Cache for LLM calls (this may be extended with a hosted cache later)
    - JSON report with commit hash, file path, line numbers and confidence scoring (categorical)
    - Secrets are redacted in the JSON output (set via --redaction flag)
    - SARIF export available (set via --sarif flag)

## Requirements
    - Python 3.8+
    - Ollama (for local LLM inference)
    - Git

## Note on LLMs
    
The current implementation uses a local Ollama model which is automatically pulled by the CLI-tool itself, however the LLM-Analysis service is decoupled from the underlying
Ollama implementation. So the system can easily be replaced with another service that calls an external LLM via API e.g. OpenAI or Anthropic. The abstract class BaseLLMProvider
may be used (defined in ollama_provider.py) to create another LLM-Client, which can then be passed in the llm_service. 
```python
def __init__(self, provider: Optional[BaseLLMProvider] = None):
self.provider = provider or OllamaProvider(auto_start=True)
```

## Setup:

1. **Clone the repo**
```bash git clone https://github.com/ErenCanYildirim/LLM-Git-Repo-Secrets-Scanner.git
cd <repo-dir>
```

2. **Install dependencies**
    ```bash pip install -r requirements.txt```

If you want to set up Ollama manually then:

1. **Install Ollama**

2. **Pull LLM model**
    ```bash ollama pull llama3.2```

Else Ollama is setup manually. 

## Usage

### Basic scan for a local repo:
```bash
python main.py --repo /path/to/repo --n 10 --out report.json
```

## Scanning a remote repo:
```bash
python main.py --repo  https://github.com/user/repo.git --n 10 --out report.json
```

## Use a different llm
```bash 
python main.py --repo <REPO> --n 10 --out report.json --model mistral:7b
```

## CLI-Options

- `--repo`: Path to local repo or remote URL (required)
- `--n`: Number of commits to scan (default: 10)
- `--out`: Output JSON file (default: report.json) 
- `--model`: Ollama model to use (default: llama3.2)
- `--verbose`: Enable debug logging
- `--redaction`: Enable redaction of found secrets in JSON (default: 1)
- `--sarif`: Exports the findings in a SARIF format

## Example Output
```json
{
 "scan_info": {
    "repository": "/path/to/repo",
    "commits_scanned": 10,
    "total_findings": 23,
    "high_confidence": 6,
    "medium_confidence": 17
  },
  "findings_by_commit": {
    "abc123...": [
      {
        "file_path": "config.py",
        "line_number": 42,
        "snippet": "AWS_SECRET_KEY = \"...",
        "finding_type": "aws_secret_key",
        "confidence": "high",
        "rationale": "Hardcoded AWS secret key"
      }
    ]
  },
    "summary": {
      "finding_types": {
        "aws_secret_key": 2,
        "password": 8,
        "api_key": 5,
        "github_token": 3,
        "jwt_token": 2,
        "private_key": 3
    }
  }
}
```

## Current secret types
    These are implemented via Regex, you may add more as you desire.

    - AWS credentials (access keys, secret keys)
    - API keys (Generic, Google, GitHub, Stripe, SendGrid, etc.)
    - Database connection strings (PostgreSQL, MongoDB, Redis)
    - JWT tokens
    - Private keys (SSH, RSA, OpenSSH)
    - Passwords

## Limitations

  - LLM response time is slow on CPU, use a GPU server or an external third-party LLM-API
  - Sequential processing is slowing down the process as of now. This may be fixed with multiple LLMs or externally hosted LLMs
  - Chunking is done in 2KB batches, more efficient methods should be implemented here
  - False positives (a few low-confidence findings may still be false positives)
  - Token limits (currently set to 10000, very large files will get truncated. Adjust this according to your system's capabilities)
  - Caching is in-memory for now, can be extended

## Acknowledgments

  Build with Ollama for local LLM inference