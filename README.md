# libnss_pwdgrpd

`libnss_pwdgrpd` is a Name Service Switch (NSS) plugin for Linux glibc that resolves user (`passwd`) and group (`group`) entries over HTTP/HTTPS REST APIs returning JSON responses.

---

## Features

* **Standard NSS Resolution:** Implements `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`, and `initgroups`.
* **User & Group Enumeration:** Supports `setpwent`, `getpwent`, `endpwent`, `setgrent`, `getgrent`, and `endgrent` (`getent passwd` and `getent group`).
* **REST & JSON Based:** Connects to an external daemon or HTTP service returning JSON structured user/group data.
* **Configurable HTTP Client:** Supports proxy setup and customizable timeouts via an INI configuration file.

---

## Dependencies

* **glibc** (GNU C Library with NSS support)
* **libcurl** (HTTP transfer engine)
* **libjson-c** (JSON parsing library)
* **inih** (`ini.h` for configuration file parsing)

On Debian/Ubuntu systems, install build dependencies via:

```bash
sudo apt-get install build-essential libcurl4-openssl-dev libjson-c-dev libinih-dev
```

---

## Configuration

The default configuration file path is `/etc/libnss-pwdgrpd.ini`.

```ini
[pwdgrpd]
endpoint = https://api.example.com
proxy = http://proxy.example.com:8080
ignore_proxy = false
timeout = 10
```

### Configuration Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `endpoint` | String | *(Required)* | Base URL for the JSON API (e.g., `[https://auth.internal](https://auth.internal)`). Must be HTTPS by default. |
| `proxy` | String | Empty | HTTP proxy URL. |
| `ignore_proxy` | Boolean | `false` | Set to `true` to force direct connection bypassing proxies. |
| `timeout` | Integer | `10` | API request timeout in seconds. |

To enable the plugin, add `pwdgrpd` to `/etc/nsswitch.conf`:

```text
passwd:     files pwdgrpd
group:      files pwdgrpd
```

---

## Expected API Specification

* A reference API server implementation could be found at: [https://github.com/leo9800/pwdgrpd](https://github.com/leo9800/pwdgrpd) *

The backing daemon or API server must expose the following REST endpoints returning JSON:

### 1. User Lookup (`/getpwnam/{username}?t=json` or `/getpwuid/{uid}?t=json`)

**HTTP Status:** `200 OK` (or `404 Not Found` if missing)

**JSON Response:**

```json
{
  "pw_name": "alice",
  "pw_passwd": "x",
  "pw_uid": 1001,
  "pw_gid": 1001,
  "pw_gecos": "Alice Smith",
  "pw_dir": "/home/alice",
  "pw_shell": "/bin/bash"
}
```

### 2. Group Lookup (`/getgrnam/{groupname}?t=json` or `/getgrgid/{gid}?t=json`)

**HTTP Status:** `200 OK` (or `404 Not Found` if missing)

**JSON Response:**

```json
{
  "gr_name": "developers",
  "gr_passwd": "x",
  "gr_gid": 2000,
  "gr_mem": ["alice", "bob"]
}
```

### 3. Group Membership (`/initgroups/{username}?t=json&b=gid`)

**HTTP Status:** `200 OK` (or `404 Not Found` if user not found)

**JSON Response:** Array of additional Group IDs (GIDs) assigned to the user.

```json
[2000, 2001, 3000]
```

### 4. Enumeration (`/getpwall?t=json` and `/getgrall?t=json`)

**HTTP Status:** `200 OK` (Return `403 Forbidden` if enumeration is not allowed by the server)

**JSON Response:** Array of user or group JSON objects.

```json
[
  {
    "pw_name": "alice",
    "pw_passwd": "x",
    "pw_uid": 1001,
    "pw_gid": 1001,
    "pw_gecos": "Alice Smith",
    "pw_dir": "/home/alice",
    "pw_shell": "/bin/bash"
  }
]
```

---

## Building and Installation

Compile the library as a shared object and install it into system library path (`/lib` or `/lib/x86_64-linux-gnu/`).

```bash
# Example compilation command
gcc -shared -fPIC -O2 \
  -Wall -Wextra \
  -o libnss_pwdgrpd.so.2 \
  nss-pwdgrpd.c \
  -lcurl -ljson-c -linih

# Install the library
sudo install -m 0755 libnss_pwdgrpd.so.2 /lib/x86_64-linux-gnu/libnss_pwdgrpd.so.2
sudo ldconfig
```