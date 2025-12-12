# Kestrel-mTLS-CTL-Example

Kestrel mutual TLS certificate trust list example.

This is an example on howto set up mTLS and sending a client-certificate trust list with Kestrel.

This dotnet-issue can be used as a starting point to explain what we want to achieve:

- [Developers using Kestrel can configure the list of CAs per-hostname #45456](https://github.com/dotnet/runtime/issues/45456)

## 1 Development

### 1.1 Briefly

This is briefly howto fix it:

#### 1.1.1 The core stuff in [Program.cs](/Source/Application/Program.cs#L9)

	builder.WebHost.ConfigureKestrel(kestrelServerOptions =>
	{
		kestrelServerOptions.ConfigureHttpsDefaults(httpsConnectionAdapterOptions =>
		{
			httpsConnectionAdapterOptions.OnAuthenticate = (_, sslServerAuthenticationOptions) =>
			{
				if(!sslServerAuthenticationOptions.ClientCertificateRequired)
					return;

				if(sslServerAuthenticationOptions.ServerCertificate is not X509Certificate2 serverCertificate)
					throw new InvalidOperationException("The server-certificate is invalid.");

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

				SslCertificateTrust? sslCertificateTrust;

				if(OperatingSystem.IsWindows())
				{
					/*
						On Windows we can only set the SSL-certificate-trust to the LocalMachine store. If not we get an exception.

						System.PlatformNotSupportedException: 'Only LocalMachine stores are supported on Windows.':

						#if TARGET_WINDOWS
							if (sendTrustInHandshake && store.Location != StoreLocation.LocalMachine)
							{
								throw new PlatformNotSupportedException(SR.net_ssl_trust_store);
							}
						#endif
					*/
					using(var store = new X509Store("Store-bc8fd192-bb7a-41a1-b470-b2c356aac15b", StoreLocation.LocalMachine)) // This store must have been set up in the Windows Certificate Manager. You can set it upp with .windows-certificate-management/Setup in this solution.
					{
						store.Open(OpenFlags.ReadOnly);

						sslCertificateTrust = SslCertificateTrust.CreateForX509Store(store, true);
					}
				}
				else
				{
					var certificates = new X509Certificate2Collection();
					certificates.ImportFromPemFile("/etc/ssl/certs/intermediate-1.crt");
					certificates.ImportFromPemFile("/etc/ssl/certs/intermediate-2.crt");

					sslCertificateTrust = SslCertificateTrust.CreateForX509Collection(certificates, true);
				}

				sslServerAuthenticationOptions.ServerCertificateContext = SslStreamCertificateContext.Create(serverCertificate, null, false, sslCertificateTrust);
			};
		});
	});

#### 1.1.2 [appsettings.json](/Source/Application/appsettings.json#L3)

	{
		...,
		"Kestrel": {
			"EndpointDefaults": {
				"ClientCertificateMode": "RequireCertificate"
			}
		},
		...
	}

##### 1.1.2.1 [appsettings.Docker.json (Linux)](/Source/Application/appsettings.Docker.json#L2)

	{
		"Kestrel": {
			"Certificates": {
				"Default": {
					"KeyPath": "/etc/ssl/private/https.key",
					"Path": "/etc/ssl/private/https.crt"
				}
			}
		}
	}

##### 1.1.2.2 [appsettings.Kestrel.json (Windows)](/Source/Application/appsettings.Kestrel.json#L2)

	{
		"Kestrel": {
			"Certificates": {
				"Default": {
					"KeyPath": "../../.certificates/https.key",
					"Path": "../../.certificates/https.crt"
				}
			}
		}
	}

#### 1.1.3 [Application.csproj](/Source/Application/Application.csproj#L5)

	<Project Sdk="Microsoft.NET.Sdk.Web">
		<PropertyGroup>
			...
			<!-- Certificates to trust -->
			<DockerfileRunArguments>-v "$(SolutionDir).certificates/intermediate-1.crt:/etc/ssl/certs/intermediate-1.crt:ro"</DockerfileRunArguments>
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/intermediate-2.crt:/etc/ssl/certs/intermediate-2.crt:ro"</DockerfileRunArguments>
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/intermediate-3.crt:/etc/ssl/certs/intermediate-3.crt:ro"</DockerfileRunArguments>
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/intermediate-4.crt:/etc/ssl/certs/intermediate-4.crt:ro"</DockerfileRunArguments>
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/root.crt:/etc/ssl/certs/root.crt:ro"</DockerfileRunArguments>
			<!-- HTTPS certificate -->
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/https.crt:/etc/ssl/private/https.crt:ro"</DockerfileRunArguments>
			<DockerfileRunArguments>$(DockerfileRunArguments) -v "$(SolutionDir).certificates/https.key:/etc/ssl/private/https.key:ro"</DockerfileRunArguments>
			...
		</PropertyGroup>
		...
	</Project>

## 2 Environment

To be able to run the application from Visual Studio when we develop there are some requirements to get it working:

- We need certificates in our certificate-store.
- We need the registry-key HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\SendTrustedIssuerList (value = 1, DWord).

### 2.1 Setup

- Run [Setup](/.windows-certificate-management/Setup) "as Administrator" to setup certificates and registry-key (SendTrustedIssuerList). You can do it by building the solution and then right-click [/.windows-certificate-management/Setup/bin/Debug/net10.0/Setup.exe](/.windows-certificate-management/Setup/bin/Debug/net10.0/Setup.exe) and choose "Run as Administrator".

Configuration: [/.windows-certificate-management/Management/appsettings.json](/.windows-certificate-management/Management/appsettings.json#L83)

- [Overview of TLS - SSL (Schannel SSP) / Management of trusted issuers for client authentication / SendTrustedIssuerList](https://learn.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview#BKMK_TrustedIssuers)

### 2.2 Cleanup

- Run [Cleanup](/.windows-certificate-management/Cleanup) "as Administrator" to cleanup/remove certificates and [possibly registry-key (SendTrustedIssuerList)](/.windows-certificate-management/Management/appsettings.json#L81). You can do it by building the solution and then right-click [/.windows-certificate-management/Cleanup/bin/Debug/net10.0/Cleanup.exe](/.windows-certificate-management/Cleanup/bin/Debug/net10.0/Cleanup.exe) and choose "Run as Administrator".

Configuration: [/.windows-certificate-management/Management/appsettings.json](/.windows-certificate-management/Management/appsettings.json#L2)

## 3 Certificates

The certificates are only for testing/laborating.

All the necessary certificate-files are included in this solution:

- [**client-1.pfx**](/.certificates/client-1.pfx) - *CERT:\\CurrentUser\\My* - password = **password**
- [**client-2.pfx**](/.certificates/client-2.pfx) - *CERT:\\CurrentUser\\My* - password = **password**
- [**client-3.pfx**](/.certificates/client-3.pfx) - *CERT:\\CurrentUser\\My* - password = **password**
- [**client-4.pfx**](/.certificates/client-4.pfx) - *CERT:\\CurrentUser\\My* - password = **password**
- [**https.crt**](/.certificates/https.crt) - used in [appsettings.Docker.json](/Source/Application/appsettings.Docker.json#L6) and [appsettings.Kestrel.json](/Source/Application/appsettings.Kestrel.json#L6) to configure the https-certificate
- [**https.key**](/.certificates/https.key) - used in [appsettings.Docker.json](/Source/Application/appsettings.Docker.json#L5) and [appsettings.Kestrel.json](/Source/Application/appsettings.Kestrel.json#L5) to configure the https-certificate
- [**intermediate-1.crt**](/.certificates/intermediate-1.crt) - *CERT:\\CurrentUser\\CA*, *CERT:\\LocalMachine\\Store-bc8fd192-bb7a-41a1-b470-b2c356aac15b* and *CERT:\\LocalMachine\\Store-c985b698-1534-440f-9857-070c8dfd6bfd*
- [**intermediate-2.crt**](/.certificates/intermediate-2.crt) - *CERT:\\CurrentUser\\CA* and *CERT:\\LocalMachine\\Store-bc8fd192-bb7a-41a1-b470-b2c356aac15b*
- [**intermediate-3.crt**](/.certificates/intermediate-3.crt) - *CERT:\\CurrentUser\\CA* and *CERT:\\LocalMachine\\Store-bc8fd192-bb7a-41a1-b470-b2c356aac15b*
- [**intermediate-4.crt**](/.certificates/intermediate-4.crt) - *CERT:\\CurrentUser\\CA*
- [**root.crt**](/.certificates/root.crt) - *CERT:\\CurrentUser\\Root*

If you want to create them yourself, you need to create the following certificate-structure.

- root
	- https
	- intermediate-1
		- client-1
	- intermediate-2
		- client-2
	- intermediate-3
		- client-3
	- intermediate-4
		- client-4

The certificates in this solution are created by using this web-application, [Certificate-Factory](https://github.com/HansKindberg-Lab/Certificate-Factory). It is a web-application you can run in Visual Studio and then upload a json-certificate-file like below.

1. **File \*** (upload a json-file like below)

		{
			"Defaults": {
				"HashAlgorithm": "Sha256",
				"NotAfter": "9999-01-01"
			},
			"Roots": {
				"root": {
					"Certificate": {
						"Subject": "CN=Kestrel-mTLS-CTL-Example Root CA"
					},
					"IssuedCertificates": {
						"https": {
							"Certificate": {
								"EnhancedKeyUsage": "ServerAuthentication",
								"KeyUsage": "DigitalSignature",
								"Subject": "CN=Kestrel-mTLS-CTL-Example https-certificate",
								"SubjectAlternativeName": {
									"DnsNames": [
										"localhost"
									]
								}
							}
						},
						"intermediate-1": {
							"Certificate": {
								"CertificateAuthority": {
									"PathLengthConstraint": 0
								},
								"KeyUsage": "KeyCertSign",
								"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 1"
							},
							"IssuedCertificates": {
								"client-1": {
									"Certificate": {
										"EnhancedKeyUsage": "ClientAuthentication",
										"KeyUsage": "DigitalSignature",
										"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 1"
									}
								}
							}
						},
						"intermediate-2": {
							"Certificate": {
								"CertificateAuthority": {
									"PathLengthConstraint": 0
								},
								"KeyUsage": "KeyCertSign",
								"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 2"
							},
							"IssuedCertificates": {
								"client-2": {
									"Certificate": {
										"EnhancedKeyUsage": "ClientAuthentication",
										"KeyUsage": "DigitalSignature",
										"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 2"
									}
								}
							}
						},
						"intermediate-3": {
							"Certificate": {
								"CertificateAuthority": {
									"PathLengthConstraint": 0
								},
								"KeyUsage": "KeyCertSign",
								"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 3"
							},
							"IssuedCertificates": {
								"client-3": {
									"Certificate": {
										"EnhancedKeyUsage": "ClientAuthentication",
										"KeyUsage": "DigitalSignature",
										"Subject": "CN=Kestrel-mTLS-CTL-Example client-certificate 3"
									}
								}
							}
						},
						"intermediate-4": {
							"Certificate": {
								"CertificateAuthority": {
									"PathLengthConstraint": 0
								},
								"KeyUsage": "KeyCertSign",
								"Subject": "CN=Kestrel-mTLS-CTL-Example Intermediate CA 4"
							},
							"IssuedCertificates": {
								"client-4": {
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
					"CertificateAuthority": true
				},
				"KeyUsage": "CrlSign, KeyCertSign"
			}
		}

2. **Archive kind \***

	Choose **\*.crt, \*.key and \*.pfx files**

3. **Flat archive**

	**Checked**

4. **Password \***

	Use **password** as password when creating the certificates.

You will then get a zip-file including all certificate-files.

## 4 Links

- [Configure endpoints for the ASP.NET Core Kestrel web server](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints)
- [Overview of TLS - SSL (Schannel SSP)](https://learn.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview)
- [Access denied when trying to load X509Certificate2 on (upgraded) Windows 10 April 2018 Update #25](https://github.com/Microsoft/dotnet-framework-early-access/issues/25)
- [Default permissions for the MachineKeys folders](https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/default-permissions-machinekeys-folders)
- [Solving Access Denied in Crypto Machine Keys](https://odetocode.com/blogs/scott/archive/2020/01/12/solving-access-denied-in-crypto-machine-keys.aspx)