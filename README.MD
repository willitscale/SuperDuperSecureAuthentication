# SuperDuperAuthentication

### Disclaimer

This is **NOT** a library which should be used for commercial purposes or in any means to protect sensitive data as it was written with a backdoor for a CTF (Capture the Flag) hacking challenge.

### Setup 

Include this with the following:

```
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/willitscale/SuperDuperSecureAuthentication"
        }
    ],
    "require": {
        "SuperDuperSecureAuthentication/SuperDuperSecureAuthentication": "master"
    }
}
```

Create a `.env` file with the following:

```
SECRET=yoursupersecretvalue
```