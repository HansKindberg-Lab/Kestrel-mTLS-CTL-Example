using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Management.Configuration
{
	public class CertificateOptions : ICloneable, IComparable<CertificateOptions>, IEquatable<CertificateOptions>
	{
		#region Properties

		public virtual string? Password { get; set; }
		public virtual string? Path { get; set; }
		public virtual StoreLocation? StoreLocation { get; set; }
		public virtual string? StoreName { get; set; }

		#endregion

		#region Methods

		object ICloneable.Clone()
		{
			return this.Clone();
		}

		public virtual CertificateOptions Clone()
		{
			var memberwiseClone = (CertificateOptions)this.MemberwiseClone();

			var clone = new CertificateOptions
			{
				Password = this.Password == null ? null : new StringBuilder(this.Password).ToString(),
				Path = this.Path == null ? null : new StringBuilder(this.Path).ToString(),
				StoreLocation = memberwiseClone.StoreLocation,
				StoreName = this.StoreName == null ? null : new StringBuilder(this.StoreName).ToString(),
			};

			return clone;
		}

		public virtual int CompareTo(CertificateOptions? other)
		{
			return string.Compare(this.ToString(), other?.ToString(), StringComparison.OrdinalIgnoreCase);
		}

		public override bool Equals(object? obj)
		{
			return this.Equals(obj as CertificateOptions);
		}

		public virtual bool Equals(CertificateOptions? other)
		{
			return other != null && this.ToString().Equals(other.ToString(), StringComparison.OrdinalIgnoreCase);
		}

		public override int GetHashCode()
		{
			return this.ToString().GetHashCode();
		}

		public static bool operator ==(CertificateOptions? left, CertificateOptions? right)
		{
			if(left is null)
				return right is null;

			return left.Equals(right);
		}

		public static bool operator >(CertificateOptions? left, CertificateOptions? right)
		{
			return left is not null && left.CompareTo(right) > 0;
		}

		public static bool operator >=(CertificateOptions? left, CertificateOptions? right)
		{
			return left is null ? right is null : left.CompareTo(right) >= 0;
		}

		public static bool operator !=(CertificateOptions? left, CertificateOptions? right)
		{
			return !(left == right);
		}

		public static bool operator <(CertificateOptions? left, CertificateOptions? right)
		{
			return left is null ? right is not null : left.CompareTo(right) < 0;
		}

		public static bool operator <=(CertificateOptions? left, CertificateOptions? right)
		{
			return left is null || left.CompareTo(right) <= 0;
		}

		public override string ToString()
		{
			var parts = new List<string>
			{
				this.Path == null ? string.Empty : $"\"{this.Path}\"",
				this.StoreLocation == null ? string.Empty : $"\"{this.StoreLocation}\"",
				this.StoreName == null ? string.Empty : $"\"{this.StoreName}\""
			};

			return string.Join("|", parts).ToLowerInvariant();
		}

		#endregion
	}
}