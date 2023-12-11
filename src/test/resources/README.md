# Test certificates

The certificates in this directory are for testing. Don't use them for anything else.

Certificates have been created using `xca` and are valid until 2044. Maybe then we'll have something that
can be automated from the CLI. The password is `test1234`.

After exporting, the need to combined:

```shell
cat test1.crt intermediate.crt ca.crt > tls.crt
cat test2.crt intermediate.crt ca.crt > fullchain1.pem
```