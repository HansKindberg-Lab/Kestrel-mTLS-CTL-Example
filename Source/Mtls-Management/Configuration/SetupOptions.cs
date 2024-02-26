namespace MtlsManagement.Configuration
{
	public class SetupOptions
	{
		#region Properties

		public virtual IList<CertificateOptions> Certificates { get; } = new List<CertificateOptions>();
		public virtual IList<RegistryKeyOptions> RegistryKeys { get; } = new List<RegistryKeyOptions>();

		#endregion
	}
}