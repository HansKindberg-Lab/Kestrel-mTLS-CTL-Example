# Certificates

- **client-certificate-1.pfx** - import to *CERT:\\CurrentUser\\My*
- **client-certificate-2.pfx** - import to *CERT:\\CurrentUser\\My*
- **client-certificate-3.pfx** - import to *CERT:\\CurrentUser\\My*
- **client-certificate-4.pfx** - import to *CERT:\\CurrentUser\\My*
- **https-certificate.crt** - use in appsettings.json to configure the https-certificate
- **https-certificate.key** - use in appsettings.json to configure the https-certificate
- **intermediate-certificate-1.crt** - trust in the Docker-container
- **intermediate-certificate-2.crt** - trust in the Docker-container
- **intermediate-certificate-3.crt** - trust in the Docker-container
- **intermediate-certificate-4.crt** - trust in the Docker-container
- **root-certificate.crt** - trust in the Docker-container

I thought if we wanted to avoid a certificate trust warning in the browser, that we could import **root-certificate.crt** to *CERT:\\CurrentUser\\Root* or *CERT:\\LocalMachine\\Root*. But that does not seem to work. I must be missing something or maybe the root-certificate is not a "correct" root-certificate, maybe some attribute missing.