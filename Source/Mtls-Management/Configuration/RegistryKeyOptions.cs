using Microsoft.Win32;

namespace MtlsManagement.Configuration
{
	public class RegistryKeyOptions
	{
		#region Properties

		public virtual string? Name { get; set; }
		public virtual string? Path { get; set; }
		public virtual RegistryRoot? Root { get; set; }
		public virtual object? Value { get; set; }
		public virtual RegistryValueKind? ValueKind { get; set; }

		#endregion
	}
}