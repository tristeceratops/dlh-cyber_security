# Python Fundamentals & Networking Cheat Sheet

---

# What is the Correct Way to Write a Python Script?

A Python script is a text file ending with `.py`.

Example:

```python
#!/usr/bin/env python3

def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
```

Structure:

```text
Imports
↓
Variables
↓
Functions
↓
Main Program
```

Benefits:

- Organized code
- Reusable functions
- Easy debugging

---

# Variables, Data Types, and Operators

## Variables

Variables store data.

```python
name = "Alice"
age = 25
```

Think of them as labeled boxes:

```text
name ──► "Alice"
age  ──► 25
```

---

## Data Types

### String

```python
text = "hello"
```

### Integer

```python
age = 25
```

### Float

```python
price = 12.99
```

### Boolean

```python
online = True
```

### List

```python
ports = [22, 80, 443]
```

### Dictionary

```python
user = {"name": "alice"}
```

---

## Operators

### Arithmetic

```python
+
-
*
/
%
**
```

Example:

```python
result = 10 + 5
```

---

### Comparison

```python
==
!=
<
>
<=
>=
```

Example:

```python
if age >= 18:
    print("Adult")
```

---

### Logical

```python
and
or
not
```

Example:

```python
if port == 80 or port == 443:
    print("Web server")
```

---

# if, elif, and else Statements

Used to make decisions.

```python
if condition:
    ...
elif condition:
    ...
else:
    ...
```

Example:

```python
port = 80

if port == 22:
    print("SSH")

elif port == 80:
    print("HTTP")

else:
    print("Unknown")
```

Flow:

```text
Condition?
    │
 ┌──┴──┐
Yes   No
 │     │
if   elif
        │
      else
```

---

# For Loop vs While Loop

## For Loop

Used when the number of iterations is known.

```python
for i in range(5):
    print(i)
```

Output:

```text
0
1
2
3
4
```

Use for:

- Lists
- Files
- Ranges

---

## While Loop

Used when the stopping condition is unknown.

```python
count = 0

while count < 5:
    print(count)
    count += 1
```

Use for:

- Waiting for input
- Network connections
- Continuous monitoring

---

# Functions

## What is a Function?

A reusable block of code.

```text
Input
 ↓
Function
 ↓
Output
```

---

## Defining a Function

```python
def greet():
    print("Hello")
```

---

## Calling a Function

```python
greet()
```

---

## Parameters

```python
def greet(name):
    print(f"Hello {name}")
```

Call:

```python
greet("Alice")
```

---

## Return Values

```python
def add(a, b):
    return a + b
```

Call:

```python
result = add(2, 3)
```

---

# Socket Module

## What is socket?

Python's built-in networking library.

Used for:

- DNS resolution
- Port scanning
- TCP communication
- UDP communication

---

## Importing

```python
import socket
```

---

## Creating a Socket

```python
sock = socket.socket()
```

TCP socket:

```python
sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)
```

---

# Common Built-in Functions

## print()

Displays output.

```python
print("Hello")
```

---

## input()

Gets user input.

```python
name = input("Name: ")
```

---

## len()

Returns length.

```python
len("hello")
```

Result:

```python
5
```

---

## open()

Opens files.

```python
open("file.txt")
```

---

# String Methods

## .strip()

Removes whitespace.

```python
text = " hello "
text.strip()
```

Result:

```text
hello
```

---

## .split()

Splits strings.

```python
text = "a,b,c"
text.split(",")
```

Result:

```python
['a', 'b', 'c']
```

---

## .format()

Formats strings.

```python
"Hello {}".format("Alice")
```

Result:

```text
Hello Alice
```

---

# Python Lists

Create:

```python
ports = [22, 80, 443]
```

---

## Access

```python
ports[0]
```

---

## Add

```python
ports.append(8080)
```

---

## Remove

```python
ports.remove(80)
```

---

## Loop

```python
for port in ports:
    print(port)
```

---

## Sort

```python
ports.sort()
```

---

# Installing Packages

Install packages with pip:

```bash
pip install requests
```

or

```bash
python3 -m pip install requests
```

---

# Using External Modules

Install:

```bash
pip install requests
pip install dnspython
pip install beautifulsoup4
```

Import:

```python
import requests
import dns.resolver
from bs4 import BeautifulSoup
```

Use:

```python
response = requests.get("https://example.com")
```

---

# Reading Documentation

When reading documentation, look for:

```text
1. Installation
2. Import examples
3. Function reference
4. Return values
5. Exceptions
6. Examples
```

Questions:

```text
What does it do?
What parameters does it need?
What does it return?
What errors can occur?
```

---

# Using Third-Party APIs

Typical workflow:

```text
API Endpoint
      ↓
HTTP Request
      ↓
Response
      ↓
Parse JSON
```

Example:

```python
import requests

response = requests.get(
    "https://api.example.com/users"
)

data = response.json()
```

Good practices:

- Read API docs
- Check status codes
- Handle errors
- Respect rate limits

---

# Reading Files

## Context Manager

Recommended approach:

```python
with open("file.txt", "r") as file:
    content = file.read()
```

Automatically closes file.

---

## Read Entire File

```python
file.read()
```

---

## Read One Line

```python
file.readline()
```

---

## Read All Lines

```python
file.readlines()
```

---

# Writing Files

Overwrite:

```python
with open("file.txt", "w") as file:
    file.write("Hello")
```

Append:

```python
with open("file.txt", "a") as file:
    file.write("World")
```

---

# Parsing Line by Line

Best approach:

```python
with open("file.txt") as file:
    for line in file:
        print(line.strip())
```

Memory efficient.

Useful for:

- Wordlists
- Logs
- CSV files
- DNS records

---

# File Modes

| Mode | Meaning |
|--------|--------|
| r | Read |
| w | Write (overwrite) |
| a | Append |

Examples:

```python
open("file.txt", "r")
open("file.txt", "w")
open("file.txt", "a")
```

---

# Resolving a Domain to an IP

Example:

```python
import socket

ip = socket.gethostbyname("google.com")

print(ip)
```

Output:

```text
142.x.x.x
```

---

# What is socket.gethostbyname()?

Resolves:

```text
Domain → IP Address
```

Example:

```python
socket.gethostbyname("example.com")
```

Equivalent concept:

```text
DNS Query
     ↓
IP Address Returned
```

---

# Advanced DNS Queries

Use:

```python
dnspython
```

Install:

```bash
pip install dnspython
```

Example:

```python
import dns.resolver

answers = dns.resolver.resolve(
    "google.com",
    "MX"
)

for answer in answers:
    print(answer)
```

Can query:

```text
A
AAAA
MX
TXT
NS
CNAME
SOA
```

---

# HTTP GET Requests

Example:

```python
import requests

response = requests.get(
    "https://example.com"
)

print(response.text)
```

---

# HTTP Request Library

Most common:

```python
requests
```

Install:

```bash
pip install requests
```

Import:

```python
import requests
```

---

# Accessing Response Headers

Example:

```python
import requests

response = requests.get(
    "https://example.com"
)

print(response.headers)
```

Specific header:

```python
print(
    response.headers["Server"]
)
```

---

# Checking if a Port is Open

Example:

```python
import socket

sock = socket.socket()

result = sock.connect_ex(
    ("192.168.1.10", 80)
)

print(result)
```

---

# What Does connect_ex() Return?

Returns:

```text
0      = Open
Other  = Error / Closed
```

Example:

```python
if result == 0:
    print("Open")
```

---

# HTML Parsing Library

Most common:

```python
BeautifulSoup
```

Install:

```bash
pip install beautifulsoup4
```

Import:

```python
from bs4 import BeautifulSoup
```

---

# What is BeautifulSoup?

HTML/XML parser.

Converts:

```html
<html>
  <title>Example</title>
</html>
```

Into a searchable object.

Example:

```python
soup.find("title")
```

Useful for:

- Web scraping
- Data extraction
- Parsing pages

---

# What Does .prettify() Do?

Formats HTML nicely.

Example:

```python
print(
    soup.prettify()
)
```

Output:

```html
<html>
 <body>
  <h1>Hello</h1>
 </body>
</html>
```

Useful for:

- Debugging
- Learning page structure

---

# What is Web Scraping?

Extracting data from webpages.

Example:

```text
Website
   ↓
Download HTML
   ↓
Parse HTML
   ↓
Extract Data
```

Example targets:

- Titles
- Prices
- Links
- Articles

Typical flow:

```python
requests
    ↓
BeautifulSoup
    ↓
Extract Data
```

---

# What is Web Crawling?

Automatically discovering webpages by following links.

Example:

```text
Page A
 ↓
Page B
 ↓
Page C
 ↓
Page D
```

Crawler:

```text
Visit page
Extract links
Visit links
Repeat
```

Used by:

- Search engines
- Site mappers
- Security tools

---

# What is Recursion?

A function calling itself.

Example:

```python
def countdown(n):

    if n == 0:
        return

    print(n)

    countdown(n - 1)
```

---

# Recursion in Web Crawling

Crawler process:

```text
Visit Page
     ↓
Find Links
     ↓
Visit Each Link
     ↓
Find More Links
     ↓
Repeat
```

Recursive example:

```python
def crawl(url):

    links = get_links(url)

    for link in links:
        crawl(link)
```

Visual:

```text
Page A
├── Page B
│   ├── Page D
│   └── Page E
│
└── Page C
    ├── Page F
    └── Page G
```

Important:

Use a "visited" set to avoid infinite loops:

```python
visited = set()
```

Otherwise:

```text
A → B → C
↑       ↓
└───────┘
```

can create endless recursion.

---

# Typical Networking & Scraping Workflow

```text
1. Resolve Domain
       ↓
socket.gethostbyname()

2. DNS Enumeration
       ↓
dnspython

3. HTTP Request
       ↓
requests.get()

4. Parse HTML
       ↓
BeautifulSoup

5. Extract Links/Data
       ↓
find_all()

6. Crawl New Pages
       ↓
Recursion

7. Save Results
       ↓
Files / Database
```