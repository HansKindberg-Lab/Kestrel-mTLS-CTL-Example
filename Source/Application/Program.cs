using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

/*
	It would be great if the code below could be accomplished by configuration. I do not know how. Now it is hard-coded.
*/
builder.WebHost.ConfigureKestrel((webHostBuilderContext, kestrelServerOptions) =>
{
	kestrelServerOptions.ConfigureHttpsDefaults(httpsConnectionAdapterOptions =>
	{
		/*
			If we want to check or customize client-certificate validation we can use the callback below.
		*/
		//httpsConnectionAdapterOptions.ClientCertificateValidation = (certificate, chain, sslPolicyErrors) =>
		//{
		//	return sslPolicyErrors == SslPolicyErrors.None;
		//};

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
	/*
		The commented code below is another way to set the trust list. But then we have to build the whole SslServerAuthenticationOptions-instance and the
		configuration from appsettings.json will not work.
	*/
	//kestrelServerOptions.ConfigureEndpointDefaults(listenOptions =>
	//{
	//	listenOptions.UseHttps((sslStream, sslClientHelloInfo, state, cancellationToken) =>
	//	{
	//		var sslServerAuthenticationOptions = new SslServerAuthenticationOptions();

	//		// ... build the SslServerAuthenticationOptions-instance as you like.

	//		return new ValueTask<SslServerAuthenticationOptions>(sslServerAuthenticationOptions);
	//	}, null);
	//});
});

builder.Services.AddRazorPages();

var app = builder.Build();
app.UseRouting();
app.MapRazorPages();
app.Run();