# Export Authy TOTP codes into Ente Auth

### iOS 
* Follow [this](https://gist.github.com/gboudreau/94bb0c11a6209c82418d01a59d958c93?permalink_comment_id=5298931#gistcomment-5298931) guid by [AlexTech01](https://gist.github.com/AlexTech01) to dump and decrypt all your totp seed codes:
    * Start [mitmprocy](https://mitmproxy.org/) `$ mitmweb --allow-hosts "api.authy.com"`
    * Set proxy on the phone
    * Download and trust the mitmproxy certificate
    * Log into your Authy account (must be logged out - may have to uninstall first)
    * Search for "authenticator_tokens" in mitmproxy and download it
    * Decrypt the export `$ python3 decrypt.py`
* Try to import them into [Ente Auth](https://ente.io/auth/) as Bitwarden export (json format)
    * If it doesn't work run `$ python3 convert.py` to convert the json into plain text file.
    * This file can now be imported into Ente Auth as Plain text.


## Sources
- [gboudreau](https://gist.github.com/gboudreau): How to export 2FA tokens from Authy - [link](https://gist.github.com/gboudreau/94bb0c11a6209c82418d01a59d958c93?permalink_comment_id=5298931).
- [AlexTech01](https://gist.github.com/AlexTech01): How to export and decrypt the tokens from unjailbroken iOs devices - [link](https://gist.github.com/gboudreau/94bb0c11a6209c82418d01a59d958c93?permalink_comment_id=5298931#gistcomment-5298931).
- Ente Auth: [Migrating from Authy ](https://help.ente.io/auth/migration-guides/authy/#method-2-1-if-the-export-worked-but-the-import-didn-t)
