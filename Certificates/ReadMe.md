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
- **root-certificate.crt** - trust in the Docker-container and if you want to avoid a certificate trust warning in the browser you can import it to *CERT:\\CurrentUser\\Root* or *CERT:\\LocalMachine\\Root*