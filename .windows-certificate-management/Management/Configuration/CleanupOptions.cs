namespace Management.Configuration
{
	public class CleanupOptions
	{
		#region Properties

		public virtual IList<CertificateOptions> Certificates { get; } = [];
		public virtual IList<string> CertificateStores { get; } = [];
		public virtual bool RemoveRegistryKeys { get; set; }

		#endregion
	}
}