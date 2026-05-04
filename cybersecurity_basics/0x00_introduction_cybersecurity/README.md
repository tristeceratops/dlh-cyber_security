# Explanations
## 0-release
### lsb_release
print distribution-specific information, read in /etc/os-release and /usr/lib/os-release
## 1-gen_password
[:alnum:] is wildcards for alphanumerical characters
### tr
flags used:
- d for delete
- c for reverse

both combined with alnum means delete all characters that are not alphanumerical
### head
flag -c for printing a specific number of bytes
## 2-sha256_validator
### sha256sum
sha256sum -c file where file value are in sha256sum output format: [hash]  [filename]
## 3-gen_key
### ssh-keygen
flags:
- b: length of the key in bytes
- f: filename used to save the keys
- P: specify paraphrase
- t: specify type of key

## 4-root_process
### grep
flag -v to reverse the grep result

`\([[:alnum:]]\{1,\}[[:space:]]\{1,\}\)\{2\}` (BRE - basic grep)

- `\(` `\)` : group (parentheses must be escaped in BRE)
- `[[:alnum:]]` : any alphanumeric character (letters + digits)
- `[[:space:]]` : any whitespace character (space, tab, etc.)
- `\{1,\}` : repeat the previous element **at least once**

Whole pattern:

- `\([[:alnum:]]\{1,\}[[:space:]]\{1,\}\)` matches:
  → one or more alphanumeric characters followed by one or more spaces

- `\{2\}` repeats this group **2 times**

