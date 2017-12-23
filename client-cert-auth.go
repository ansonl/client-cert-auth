package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"io/ioutil"
	"golang.org/x/crypto/acme/autocert"
	"os"
	"sync"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"bytes"
	"io"
)

var baseURL = "https://navfit99.github.io"
var noCertURL = fmt.Sprintf("%s%s", baseURL, "/?authError=1")
var verifyFailedURL = fmt.Sprintf("%s%s", baseURL, "/?authError=2")
var verifySuccessURL = fmt.Sprintf("%s%s", baseURL, "/user.html")

var certManager autocert.Manager

var caRootDirectory = "ca-roots";
var caRootPool *x509.CertPool

var caIntermediateDirectory = "ca-intermediates";
var caIntermediatePool *x509.CertPool

func parseResponse(response []byte, issuer *x509.Certificate) int {
	resp, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		log.Println("error parsing response: ", err)
		return ocsp.ServerFailed
	}
	return resp.Status
}

func checkOCSP(user *x509.Certificate, issuer *x509.Certificate) int {
	if (len(user.OCSPServer) == 0) {
		return ocsp.ServerFailed
	}

	ocspURL := user.OCSPServer[0]
	ocspReq, err := ocsp.CreateRequest(user, issuer, nil)
	if err != nil {
		log.Println("error creating ocsp request: ", err)
	}

	body := bytes.NewReader(ocspReq)
	req, err := http.NewRequest("POST", ocspURL, body)
	if err != nil {
		log.Println("error creating http post request: ", err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("error sending post request: ", err)
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	return parseResponse(buf.Bytes(), issuer)
}

func verifyClient(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v TLS Peer Certificates provided.", len(r.TLS.PeerCertificates));

	if len(r.TLS.PeerCertificates) < 1 {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		http.Redirect(w, r, noCertURL, 303)
		return
	}

	//If user provides more than one peer certificate, use extra certificates as intermediate certificates.
	//Otherwise use the preloaded intermediate pool.
	intermediateCertPool := caIntermediatePool

	if len(r.TLS.PeerCertificates) > 1 {
		intermediateCertPool = x509.NewCertPool()
		for _, peerCert := range r.TLS.PeerCertificates[1:] {
			intermediateCertPool.AddCert(peerCert)
		}
	}

	userCert := r.TLS.PeerCertificates[0]

	verifyOpts := x509.VerifyOptions{Intermediates: intermediateCertPool, Roots: caRootPool,}

	chains, err := userCert.Verify(verifyOpts)
	if err != nil {
		log.Printf("%v for certificate with Subject.CommonName %v and SerialNumber %v", err.Error(), userCert.Subject.CommonName, (*userCert.SerialNumber).String())
		//log.Printf("%v for certificate with SerialNumber %v", err.Error(), *userCert.SerialNumber)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		http.Redirect(w, r, verifyFailedURL, 303)
		return
	}

	//Display certificate chain using CommonName
	for _, chain := range chains {
		var chainCommonNames string
		for i, cert := range chain {
			if i > 0 {
				chainCommonNames = fmt.Sprintf(" → %s", chainCommonNames)
			}

			chainCommonNames = fmt.Sprintf("%s%s", cert.Subject.CommonName, chainCommonNames)
		}
		log.Printf("Locally verified chain: %s", chainCommonNames)
	}

	/*
	OCSPfailed := false;
	if r.TLS.OCSPResponse == nil {
		var allChainsWG sync.WaitGroup
		
		for _, chain := range chains {
			//Check OSCP of chain
			if len(chain) > 1 {
				for i, _ := range chain[:len(chain)-1] {
					allChainsWG.Add(1)

					log.Println(chain[i].Subject.CommonName)
					log.Println(chain[i+1].Subject.CommonName)

					go func(user *x509.Certificate, issuer *x509.Certificate) {
						var chainOCSPStatus int;
						chainOCSPStatus = checkOCSP(user, issuer)
						//chainOCSPStatus = ocsp.Good
						
						switch chainOCSPStatus {
							case ocsp.Good:
								break
							case ocsp.Revoked:
							case ocsp.Unknown:
							default:
								OCSPfailed = true
						}

						//Display OCSP status for portion of chain
						var OCSPStatusText string
						switch chainOCSPStatus {
							case ocsp.Good:
								OCSPStatusText = "Good"
								break
							case ocsp.Revoked:
								OCSPStatusText = "Revoked"
								break
							case ocsp.Unknown:
								OCSPStatusText = "Unknown"
								break;
							case ocsp.ServerFailed:
								OCSPStatusText = "Server Failed"
								break;
						}
						log.Printf("OCSP %s for %s → %s", OCSPStatusText, issuer.Subject.CommonName, user.Subject.CommonName);

						allChainsWG.Done()
					}(chain[i], chain[i+1])
				}
			}
		}

		allChainsWG.Wait()
		
	} else {
		if len(chains) > 0 && len(chains[0]) > 1 {
			
			switch parseResponse(r.TLS.OCSPResponse, chains[0][1]) {
				case ocsp.Good:
					break
				case ocsp.Revoked:
				case ocsp.Unknown:
				default:
					OCSPfailed = true
			}
		} else {
			log.Println("Stapled OCSP response found but no chain found.")
		}
	}

	if OCSPfailed {
		log.Println("One or more portions of chain failed OCSP.")
	} else {
		log.Println("All chains passed OCSP.")
	}
	*/

	authToken := setAuthTokenForUser(userCert.Subject.CommonName)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	//If user has verified locally, assume success. Don't use OCSP.
	redirectURL := fmt.Sprintf("%v?user=%s&token=%s", verifySuccessURL, userCert.Subject.CommonName, authToken)
	http.Redirect(w, r, redirectURL, 303)

}

func server(wg *sync.WaitGroup, config *tls.Config) {
	//server := http.Server{Addr: ":" + os.Getenv("PORT"), TLSConfig: config}
	server := http.Server{Addr: ":https", TLSConfig: config}

	//Verify client cert
	http.HandleFunc("/verify", verifyClient)

	//Logout client authtoken
	http.HandleFunc("/logout", logoutClient)

	/*
	http.HandleFunc("/uptime", uptimeHandler)
	http.HandleFunc("/about", aboutHandler)
	http.HandleFunc("/", rootHandler)
	*/

	err := server.ListenAndServeTLS("", "");
	if err != nil {
		panic(err)
	}

	log.Println("Server ended on port " + os.Getenv("PORT"))

	wg.Done()
}

func loadCertPoolWithFiles(certPool **x509.CertPool, filenames []string) {
	*certPool = x509.NewCertPool();

	for _, fn := range filenames {
		//Read cert file
   	certBytes, err := ioutil.ReadFile(fn);
   	if err != nil {
			log.Printf("%v for certificate %v", err, fn);
			continue;
		}

		certs, err := x509.ParseCertificates(certBytes)
		if err != nil {
		  log.Printf("%v for certificate %v", err, fn);
			continue;
		}

		for _, cert := range certs {
			(*certPool).AddCert(cert);
			log.Printf("%s certificate added to pool.", cert.Subject.CommonName);
		}
	}
}

func loadCertPoolWithFilesInDirectory(certPool **x509.CertPool, directoryName string) {
	files, err := ioutil.ReadDir(directoryName)
	if err != nil {
		log.Fatal("Loading directory %v %v", directoryName, err)
	}

	var filenameList []string
	for _, file := range files {
		filenameList = append(filenameList, fmt.Sprintf("%v/%v", directoryName, file.Name()))
	}

	loadCertPoolWithFiles(certPool, filenameList)
}

func main() {
	log.Println(noCertURL);
	log.Println(verifyFailedURL);
	log.Println(verifySuccessURL);

	//Load Root and Intermediate certificate pools for use in verification
	loadCertPoolWithFilesInDirectory(&caRootPool, caRootDirectory);
	loadCertPoolWithFilesInDirectory(&caIntermediatePool, caIntermediateDirectory);

	//Configure autocert for Lets Encrypt
	certManager = autocert.Manager{
	  Prompt:     autocert.AcceptTOS,
	  HostPolicy: autocert.HostWhitelist("runs.io"), //your domain here
	  Cache:      autocert.DirCache("./server-certs"), //folder for storing certificates
	  Email: "anson@ansonliu.com",
	}

	//Configure TLS for http server
	config := tls.Config{
		//RootCAs: caRootPool,
		//ClientCAs: caRootPool,
		//Certificates: []tls.Certificate{cert},
		GetCertificate: certManager.GetCertificate,
		//MinVersion: tls.VersionSSL30, //don't use SSLv3,
		//https://www.openssl.org/~bodo/ssl-poodle.pdf
		MinVersion: tls.VersionTLS10,
		//MinVersion: tls.VersionTLS11,
		//MinVersion: tls.VersionTLS12,
		// ClientAuth: tls.VerifyClientCertIfGiven,
		ClientAuth: tls.RequestClientCert,
		// ClientAuth: tls.RequireAnyClientCert,
		//ClientAuth: tls.RequireAndVerifyClientCert,
	}
	config.Rand = rand.Reader


	//Setup redis connection pool
	redisPool = createRedisPool()


	//start server and wait
	var wg sync.WaitGroup
	wg.Add(1)
	go server(&wg, &config)
	wg.Wait()
}
