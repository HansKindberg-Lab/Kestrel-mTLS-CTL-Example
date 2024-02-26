using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using MtlsManagement.Configuration;
using MtlsManagement.Internal;
using MtlsManagement.Security.Principal.Extensions;

[assembly: SupportedOSPlatform("Windows")]

namespace MtlsManagement
{
	public class MtlsManager
	{
		#region Fields

		private CleanupOptions? _cleanupOptions;
		private static MtlsManager? _instance;
		private SetupOptions? _setupOptions;

		#endregion

		#region Constructors

		private MtlsManager()
		{
			var baseDirectory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
			this.ApplicationDirectory = baseDirectory.Parent!.Parent!.Parent!;

			var configurationBuilder = new ConfigurationBuilder()
				.SetBasePath(baseDirectory.FullName)
				.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

			this.Configuration = configurationBuilder.Build();
		}

		#endregion

		#region Properties

		private DirectoryInfo ApplicationDirectory { get; }

		private CleanupOptions CleanupOptions
		{
			get
			{
				if(this._cleanupOptions == null)
				{
					var cleanupOptions = new CleanupOptions();
					this.Configuration.GetSection("Cleanup").Bind(cleanupOptions);
					this._cleanupOptions = cleanupOptions;
				}

				return this._cleanupOptions;
			}
		}

		private IConfiguration Configuration { get; }
		private static MtlsManager Instance => _instance ??= new MtlsManager();

		private SetupOptions SetupOptions
		{
			get
			{
				if(this._setupOptions == null)
				{
					var setupOptions = new SetupOptions();
					this.Configuration.GetSection("Setup").Bind(setupOptions);
					this._setupOptions = setupOptions;
				}

				return this._setupOptions;
			}
		}

		#endregion

		#region Methods

		public static void Cleanup()
		{
			WriteLine("Cleanup ...");
			WriteEmptyLine();

			if(ValidateElevatedPrivileges())
			{
				Instance.CleanupCertificates();
				CleanupCertificateStores();

				if(Instance.CleanupOptions.RemoveRegistryKeys)
					Instance.CleanupRegistryKeys();
			}

			WriteEnd();
		}

		private void CleanupCertificates()
		{
			WriteLine("Cleanup certificates ...");
			WriteEmptyLine();

			var certificates = new SortedSet<CertificateOptions>(this.SetupOptions.Certificates);

			foreach(var certificate in this.CleanupOptions.Certificates)
			{
				var currentUserCertificate = certificate.Clone();
				currentUserCertificate.StoreLocation = StoreLocation.CurrentUser;
				certificates.Add(currentUserCertificate);

				var localMachineCertificate = certificate.Clone();
				localMachineCertificate.StoreLocation = StoreLocation.LocalMachine;
				certificates.Add(localMachineCertificate);
			}

			foreach(var certificate in certificates)
			{
				var path = this.ResolvePath(certificate.Path);

				WriteLine($"Certificate: \"{certificate.Path}\", {certificate.StoreLocation}/{certificate.StoreName}");

				try
				{
					var exists = false;
					var registryRoot = certificate.StoreLocation == StoreLocation.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
					var storeExists = GetCertificateStores(registryRoot).Contains(certificate.StoreName, StringComparer.OrdinalIgnoreCase);
					X509Certificate2? x509Certificate = null;

					if(storeExists)
					{
						x509Certificate = new X509Certificate2(path, certificate.Password);

						try
						{
							using(var store = new X509Store(certificate.StoreName!, certificate.StoreLocation!.Value))
							{
								store.Open(OpenFlags.OpenExistingOnly);

								exists = store.Certificates.Contains(x509Certificate);
							}
						}
						// ReSharper disable EmptyGeneralCatchClause
						catch { }
						// ReSharper restore EmptyGeneralCatchClause
					}

					if(exists && x509Certificate != null)
					{
						WriteLine("Removing certificate ...");

						try
						{
							using(var store = new X509Store(certificate.StoreName!, certificate.StoreLocation!.Value))
							{
								store.Open(OpenFlags.ReadWrite);

								store.Remove(x509Certificate);
							}

							WriteGreenLine("Certificate removed.");
						}
						catch(Exception exception)
						{
							WriteRedLine($"Certificate NOT removed: {exception}");
						}
					}
					else
					{
						WriteLine("Does not exist.");
					}
				}
				catch(Exception exception)
				{
					WriteRedLine($"{exception}");
				}

				WriteEmptyLine();
			}
		}

		private static void CleanupCertificateStores()
		{
			WriteLine("Cleanup certificate-stores ...");
			WriteEmptyLine();

			const string storeName = ConfigurationKeys.IntermediateCertificateStoreName;

			foreach(var storeLocation in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
			{
				WriteLine($"Certificate-store: {storeLocation}/{storeName}");

				try
				{
					var registryRoot = storeLocation == StoreLocation.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;

					var exists = GetCertificateStores(registryRoot).Contains(storeName, StringComparer.OrdinalIgnoreCase);

					if(exists)
					{
						var internalStoreLocation = storeLocation == StoreLocation.LocalMachine ? WindowsCryptographic.CertificateStoreLocalMachine : WindowsCryptographic.CertificateStoreCurrentUser;

						WriteLine("Removing certificate-store ...");

						try
						{
							WindowsCryptographic.CertUnregisterSystemStore(ConfigurationKeys.IntermediateCertificateStoreName, WindowsCryptographic.CertificateStoreDelete | internalStoreLocation);

							WriteGreenLine("Certificate-store removed.");
						}
						catch(Exception exception)
						{
							WriteRedLine($"Certificate-store NOT removed: {exception}");
						}
					}
					else
					{
						WriteLine("Does not exist.");
					}
				}
				catch(Exception exception)
				{
					WriteRedLine($"{exception}");
				}

				WriteEmptyLine();
			}
		}

		private void CleanupRegistryKeys()
		{
			WriteLine("Cleanup registry-keys ...");
			WriteEmptyLine();

			foreach(var registryKey in this.SetupOptions.RegistryKeys)
			{
				WriteLine($"Registry-key: {registryKey.Root} | {registryKey.Path} | {registryKey.Name}");

				try
				{
					bool exists;
					var registryRoot = GetRegistryRoot(registryKey.Root!.Value);

					using(var key = registryRoot.OpenSubKey(registryKey.Path!, false))
					{
						exists = key!.GetValueNames().Contains(registryKey.Name);
					}

					if(exists)
					{
						WriteLine("Removing registry-key ...");

						try
						{
							using(var key = registryRoot.OpenSubKey(registryKey.Path!, true))
							{
								key!.DeleteValue(registryKey.Name!);
							}

							WriteGreenLine("Registry-key removed.");
						}
						catch(Exception exception)
						{
							WriteRedLine($"Registry-key NOT removed: {exception}");
						}
					}
					else
					{
						WriteLine("Does not exist.");
					}
				}
				catch(Exception exception)
				{
					WriteRedLine($"{exception}");
				}

				WriteEmptyLine();
			}
		}

		private static IEnumerable<string> GetCertificateStores(RegistryKey registryRoot)
		{
			using(var key = registryRoot.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates", false))
			{
				return key!.GetSubKeyNames();
			}
		}

		private static RegistryKey GetRegistryRoot(RegistryRoot registryRoot)
		{
			return registryRoot switch
			{
				RegistryRoot.ClassesRoot => Registry.ClassesRoot,
				RegistryRoot.CurrentConfig => Registry.CurrentConfig,
				RegistryRoot.CurrentUser => Registry.CurrentUser,
				RegistryRoot.LocalMachine => Registry.LocalMachine,
				RegistryRoot.PerformanceData => Registry.PerformanceData,
				RegistryRoot.Users => Registry.Users,
				_ => throw new InvalidOperationException("No such registry-root."),
			};
		}

		private string ResolvePath(string? path)
		{
			path = Path.Combine(this.ApplicationDirectory.FullName, path ?? string.Empty);
			path = Path.GetFullPath(path);

			return path;
		}

		public static void Setup()
		{
			WriteLine("Setup ...");
			WriteEmptyLine();

			if(ValidateElevatedPrivileges())
			{
				Instance.SetupCertificates();
				Instance.SetupRegistryKeys();
			}

			WriteEnd();
		}

		private void SetupCertificates()
		{
			WriteLine("Setup certificates ...");
			WriteEmptyLine();

			foreach(var certificate in this.SetupOptions.Certificates)
			{
				var path = this.ResolvePath(certificate.Path);

				WriteLine($"Certificate: \"{certificate.Path}\", {certificate.StoreLocation}/{certificate.StoreName}");

				WriteLine("Adding certificate ...");

				try
				{
					using(var store = new X509Store(certificate.StoreName!, certificate.StoreLocation!.Value))
					{
						store.Open(OpenFlags.ReadWrite);

						store.Add(new X509Certificate2(path, certificate.Password));
					}

					WriteGreenLine("Certificate added.");
				}
				catch(Exception exception)
				{
					WriteRedLine($"Certificate NOT added: {exception}");
				}

				WriteEmptyLine();
			}
		}

		private void SetupRegistryKeys()
		{
			WriteLine("Setup registry-keys ...");
			WriteEmptyLine();

			foreach(var registryKey in this.SetupOptions.RegistryKeys)
			{
				WriteLine($"Registry-key: {registryKey.Root} | {registryKey.Path} | {registryKey.Name} | {registryKey.Value} | {registryKey.ValueKind}");

				WriteLine("Setting registry-key ...");

				try
				{
					var registryRoot = GetRegistryRoot(registryKey.Root!.Value);

					using(var key = registryRoot.OpenSubKey(registryKey.Path!, true))
					{
						key!.SetValue(registryKey.Name!, registryKey.Value!, registryKey.ValueKind!.Value);
					}

					WriteGreenLine("Registry-key set.");
				}
				catch(Exception exception)
				{
					WriteRedLine($"Registry-key NOT set: {exception}");
				}
			}

			WriteEmptyLine();
		}

		private static bool ValidateElevatedPrivileges()
		{
			if(WindowsIdentity.GetCurrent().HasElevatedPrivileges())
				return true;

			WriteRedLine("You need to run this program with elevated privileges, \"Run as Administrator\".");
			WriteEmptyLine();

			return false;
		}

		private static void WriteEmptyLine()
		{
			Console.WriteLine();
		}

		private static void WriteEnd()
		{
			WriteLine("Press any key to close this window ...");
			Console.ReadKey();
		}

		private static void WriteGreenLine(string? value)
		{
			WriteLine(value, ConsoleColor.Green);
		}

		private static void WriteLine(string? value, ConsoleColor? color = null)
		{
			var foregroundColor = Console.ForegroundColor;

			if(color != null)
				Console.ForegroundColor = color.Value;

			Console.WriteLine(value);

			if(color != null)
				Console.ForegroundColor = foregroundColor;
		}

		private static void WriteRedLine(string? value)
		{
			WriteLine(value, ConsoleColor.Red);
		}

		#endregion
	}
}