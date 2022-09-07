# Kestrel-mTLS-CTL-Example

Kestrel mutual TLS certificate trust list example.

This is an example on howto set up mTLS and sending a client-certificate trust list with Kestrel.

This dotnet-issue can be used as a starting point to explain what we want to achieve:

- [Developers using Kestrel can configure the list of CAs per-hostname #45456](https://github.com/dotnet/runtime/issues/45456)

This example works when running Kestrel on Linux (by usig Docker). I have not got it working running Kestrel on Windows.

We need net 7 to get it working. When writing this, Dotnet SDK 7 preview 7 is the latest preview. To install:

- [Download .NET SDKs for Visual Studio](https://dotnet.microsoft.com/en-us/download/visual-studio-sdks)

## 1 Briefly

This is briefly howto fix it:

### 1.1 The core stuff in [Program.cs](/Source/Application/Program.cs#L9)

	builder.WebHost.ConfigureKestrel((webHostBuilderContext, kestrelServerOptions) =>
	{
		kestrelServerOptions.ConfigureHttpsDefaults(httpsConnectionAdapterOptions =>
		{
			httpsConnectionAdapterOptions.OnAuthenticate = (connectionContext, sslServerAuthenticationOptions) =>
			{
				if(!sslServerAuthenticationOptions.ClientCertificateRequired)
					return;

				sslServerAuthenticationOptions.CertificateChainPolicy = new X509ChainPolicy
				{
					/*
						RevocationMode = X509RevocationMode.NoCheck
						We only set this value because we are using certificates created by ourselves. The default value for RevocationMode is X509RevocationMode.Online
						and that value should be used when using "real" certificates. If we use X509RevocationMode.Online when using the certificates in this solution we
						will get client-certificate validation errors.
					*/
					RevocationMode = X509RevocationMode.NoCheck,
					/*
						TrustMode = X509ChainTrustMode.System
						We use the system for trust. As we have imported the intermediate- and root-certificates to the container it should work. The other value
						is X509ChainTrustMode.CustomRootTrust. I do not know what is required to do when using that value. But using the system-trust feels more safe. 
					*/
					TrustMode = X509ChainTrustMode.System
				};

				var certificates = new X509Certificate2Collection();
				certificates.ImportFromPemFile("Certificates/intermediate-certificate-1.crt");
				certificates.ImportFromPemFile("Certificates/intermediate-certificate-2.crt");

				var sslCertificateTrust = SslCertificateTrust.CreateForX509Collection(certificates, true);

				sslServerAuthenticationOptions.ServerCertificateContext = SslStreamCertificateContext.Create((X509Certificate2)sslServerAuthenticationOptions.ServerCertificate, null, false, sslCertificateTrust);
			};
		});
	});

### 1.2 [appsettings.json](/Source/Application/appsettings.json#L3)

	{
		...,
		"Kestrel": {
			"Certificates": {
				"Default": {
					"KeyPath": "Certificates/https-certificate.key",
					"Path": "Certificates/https-certificate.crt"
				}
			},
			"EndpointDefaults": {
				"ClientCertificateMode": "RequireCertificate"
			}
		},
		...
	}

## 2 Environment

The development-environment used when testing this example:

- Windows 10 (1909, 18363.2274)
- Docker Desktop 4.12.0 (85629)
- Visual Studio Enterprise 2022 (17.3.3)

## 3 Certificates

pfx-password: **password**

In this example the client-certificate trust list will contain 2 intermediate certificates which will result in a certificate popup with two client certificates, client-certificate-1 and client-certificate-2. So even if we have client-certificate-3 and client-certificate-4 in our certificate-store we will not get them in the certificate popup.

All the necessary certificate-files are included in this solution:

- [/Source/Application/Certificates](/Source/Application/Certificates)

If you want to create them yourself, you need to create the following certificate-structure.

- root-certificate
	- https-certificate
	- intermediate-certificate-1
		- client-certificate-1
	- intermediate-certificate-2
		- client-certificate-2
	- intermediate-certificate-3
		- client-certificate-3
	- intermediate-certificate-4
		- client-certificate-4

The certificates in this solution are created by using this web-application, [Certificate-Factory](https://github.com/HansKindberg-Lab/Certificate-Factory). It is a web-application you can run in Visual Studio and then upload a json-certificate-file like this:

	{
		"Defaults": {
			"HashAlgorithm": "Sha256",
			"NotAfter": "2050-01-01"
		},
		"Roots": {
			"root-certificate": {
				"Certificate": {
					"Subject": "CN=Kestrel-mTLS-CTL-Example Root CA"
				},
				"IssuedCertificates": {
					"https-certificate": {
						"Certificate": {
							"EnhancedKeyUsage": "ServerAuthentication",
							"KeyUsage": "DigitalSignature",
							"Subject": "CN=Kestrel-mTLS-CTL-Example https-certificate",
							"SubjectAlternativeName": {
								"DnsNames": [
									"*"
								]
							}
						}
					},
					"intermediate-certificate-1": {
						"Certificate": {
							"CertificateAuthority": {
								"PathLengthConstraint": 0
							},
							"KeyUsage": "KeyCertSign",
							"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 1"
						},
						"IssuedCertificates": {
							"client-certificate-1": {
								"Certificate": {
									"EnhancedKeyUsage": "ClientAuthentication",
									"KeyUsage": "DigitalSignature",
									"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 1"
								}
							}
						}
					},
					"intermediate-certificate-2": {
						"Certificate": {
							"CertificateAuthority": {
								"PathLengthConstraint": 0
							},
							"KeyUsage": "KeyCertSign",
							"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 2"
						},
						"IssuedCertificates": {
							"client-certificate-2": {
								"Certificate": {
									"EnhancedKeyUsage": "ClientAuthentication",
									"KeyUsage": "DigitalSignature",
									"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 2"
								}
							}
						}
					},
					"intermediate-certificate-3": {
						"Certificate": {
							"CertificateAuthority": {
								"PathLengthConstraint": 0
							},
							"KeyUsage": "KeyCertSign",
							"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 3"
						},
						"IssuedCertificates": {
							"client-certificate-3": {
								"Certificate": {
									"EnhancedKeyUsage": "ClientAuthentication",
									"KeyUsage": "DigitalSignature",
									"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 3"
								}
							}
						}
					},
					"intermediate-certificate-4": {
						"Certificate": {
							"CertificateAuthority": {
								"PathLengthConstraint": 0
							},
							"KeyUsage": "KeyCertSign",
							"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 4"
						},
						"IssuedCertificates": {
							"client-certificate-4": {
								"Certificate": {
									"EnhancedKeyUsage": "ClientAuthentication",
									"KeyUsage": "DigitalSignature",
									"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 4"
								}
							}
						}
					}
				}
			}
		},
		"RootsDefaults": {
			"CertificateAuthority": {
				"PathLengthConstraint": null
			},
			"KeyUsage": "KeyCertSign"
		}
	}

You will then get a zip-file including all certificate-files.

## 4 Send trusted issuer list on Windows

Haven't got it working on Windows. Registry settings may be involved to get it working on Windows.

- [Overview of TLS - SSL (Schannel SSP)](https://docs.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview)
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\SendTrustedIssuerList

## 5 Links

- [Configure endpoints for the ASP.NET Core Kestrel web server](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints)