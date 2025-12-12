namespace Management.Configuration
{
	public class SetupOptions
	{
		#region Properties

		public virtual IList<CertificateOptions> Certificates { get; } = [];
		public virtual IList<RegistryKeyOptions> RegistryKeys { get; } = [];

		#endregion
	}
}