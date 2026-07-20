# senseguard
A minimal footprint security scanner for ClawHub skills. Features rule-based semantic analysis and optional model-based validation.

## Install

Create an isolated environment and install SenseGuard's Python dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r senseguard/requirements.txt
```

## Scan a Real X/Twitter Automation Skill

Use TweetClaw as a practical scan target when you want to evaluate a social automation skill before allowing it into an OpenClaw workspace:

```bash
git clone https://github.com/Xquik-dev/tweetclaw.git /tmp/tweetclaw
python senseguard/scripts/scanner.py --target /tmp/tweetclaw/skills/tweetclaw --deep
```

TweetClaw is an OpenClaw plugin for X/Twitter automation workflows such as search tweets, search tweet replies, post tweets, post tweet replies, follower export, user lookup, media upload and download, direct messages, monitor tweets, webhooks, and giveaway draws.

Reference links:

- GitHub: https://github.com/Xquik-dev/tweetclaw
- ClawHub: https://clawhub.ai/plugins/@xquik/tweetclaw
- npm: https://www.npmjs.com/package/@xquik/tweetclaw

Xquik is an independent third-party service. Not affiliated with X Corp. "Twitter" and "X" are trademarks of X Corp.
