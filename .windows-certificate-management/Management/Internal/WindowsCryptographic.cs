using System.Runtime.InteropServices;

namespace Management.Internal
{
	/// <summary>
	/// Removing a Windows System Certificate Store: http://www.digitallycreated.net/Blog/58/removing-a-windows-system-certificate-store
	/// </summary>
	public static partial class WindowsCryptographic
	{
		#region Fields

		public const uint CertificateStoreCurrentUser = CertificateStoreCurrentUserId << CertificateStoreLocationShift;
		public const uint CertificateStoreCurrentUserId = 1;
		public const uint CertificateStoreDelete = 0x10;
		public const uint CertificateStoreLocalMachine = CertificateStoreLocalMachineId << CertificateStoreLocationShift;
		public const uint CertificateStoreLocalMachineId = 2;
		public const int CertificateStoreLocationShift = 16;

		#endregion

		#region Methods

		/// <summary>
		/// WindowsCryptographic.CertUnregisterSystemStore(storeName, WindowsCryptographic.CertificateStoreDelete | WindowsCryptographic.CertificateStoreCurrentUser);
		/// WindowsCryptographic.CertUnregisterSystemStore(storeName, WindowsCryptographic.CertificateStoreDelete | WindowsCryptographic.CertificateStoreLocalMachine);
		/// </summary>
		[LibraryImport("crypt32.dll", StringMarshalling = StringMarshalling.Utf16)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static partial bool CertUnregisterSystemStore(string systemStore, uint flags);

		#endregion
	}
}