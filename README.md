# Client-Cert-Auth
### HTTPS server that verifies client certificate authenticity.

##### Part of NAVFITOnline project [navfit99-js](https://github.com/ansonl/navfit99-js) and [navfit99-server](https://github.com/ansonl/navfit99-server)

#### Steps:

1. Install Go.
2. Get code with `git clone https://github.com/ansonl/client-cert-auth.git` or `go get github.com/ansonl/client-cert-auth`.
3.  Create system user with no login to run the program. `useradd -r -s /bin/false liusystem`
4. If needing Redis auth token capability, create shell script `./setEnvVar.sh` containing `export REDIS_URL=XXX`. *XXX* is the Redis connection URL.
5. Run `./grantCapabilityAndRun.sh`. The script does the following:
  - Compile and install *client-cert-auth*  according to your Go setup.
  - Run `./setEnvVar.sh` to set *$REDIS_URL*.
  - Run `setcap` to set port binding capability on program executable.
  - Run *client-cert-auth* as the created system user. 


#### Features

- [`acme/autocert`](https://godoc.org/golang.org/x/crypto/acme/autocert) integrated to use [Let's Encrypt](https://letsencrypt.org/) certificates for machine. 
- Displays the verified certificate chain when presented with client certificate.
- OCSP checking (commented out)
- Redirect to URLs based on
  - No client certificate presented
  - Invalid client certificate presented (failed verification)
  - Verified client certificate presented
- Generates random UUID on user request and stores in a REDIS database using the client certificate Subject.CommonName as user unique identifier.


#### Verifying DoD Common Access Card (CAC):

- You can find the most up to date DoD root and intermediate certificates at [DISA IASE tools](https://iase.disa.mil/pki-pke/Pages/tools.aspx) as *PKI CA Certificate Bundles: PKCS#7*. 

#### References:
https://github.com/jcbsmpsn/golang-https-example
https://github.com/alexmullins/ocspchecker
