namespace MtlsManagement.Configuration
{
	public class CleanupOptions
	{
		#region Properties

		public virtual IList<CertificateOptions> Certificates { get; } = new List<CertificateOptions>();
		public virtual bool RemoveRegistryKeys { get; set; }

		#endregion
	}
}