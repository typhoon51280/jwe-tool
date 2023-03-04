# jwe-tool

## Private Key
The private key must have no password.
If you need to remove the password protection just export a new key from the current one specifying empty password when asked:
```
openssl rsa -in private_protected.key -out private.pem
```

## Decrypt

### From file to stdout
```
jwe-tool -command decrypt -key private.key -in data.enc
```

### From command line input to stdout
```
jwe-tool -command decrypt -key private.key -token <token>
```

## Encrypt

## Verify

## Sign