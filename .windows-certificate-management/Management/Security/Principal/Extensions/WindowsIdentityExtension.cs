using System.Security.Principal;

namespace Management.Security.Principal.Extensions
{
	public static class WindowsIdentityExtension
	{
		#region Methods

		/// <summary>
		/// https://github.com/falahati/UACHelper/blob/master/UACHelper/UACHelper.cs#L85
		/// </summary>
		public static bool HasElevatedPrivileges(this WindowsIdentity windowsIdentity)
		{
			return new WindowsPrincipal(windowsIdentity).IsInRole(WindowsBuiltInRole.Administrator);
		}

		#endregion
	}
}