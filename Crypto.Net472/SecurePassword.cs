using System;
using System.Security.Cryptography;

namespace NIHE.Cryptography
{
	public class SecurePassword
	{
		private readonly byte[] _hash;
		public byte[] GetHash()
		{
			// Need to return a clone of the array so that consumers
			// of this library cannot change its contents
			return (byte[])_hash.Clone();
		}

		private readonly byte[] _salt;
		public byte[] GetSalt()
		{
			// Need to return a clone of the array so that consumers
			// of this library cannot change its contents
			return (byte[])_salt.Clone();
		}

		public int IterationCount { get; set; }

		public SecurePassword(string password)
		{
			byte[] salt = Vault.CreateSalt();
			Rfc2898DeriveBytes hashTool = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA512);

			_hash = hashTool.GetBytes(24);
			_salt = hashTool.Salt;
			IterationCount = hashTool.IterationCount;
		}

		public SecurePassword(string password, byte[] salt)
		{
			Rfc2898DeriveBytes hashTool = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA512);

			_hash = hashTool.GetBytes(24);
			_salt = hashTool.Salt;
			IterationCount = hashTool.IterationCount;
		}

		public SecurePassword(string password, byte[] salt, int iterationCount)
		{
			Rfc2898DeriveBytes hashTool = new Rfc2898DeriveBytes(password, salt, iterationCount, HashAlgorithmName.SHA512);

			_hash = hashTool.GetBytes(24);
			_salt = hashTool.Salt;
			IterationCount = hashTool.IterationCount;
		}

		public SecurePassword(Rfc2898DeriveBytes hashTool)
		{
			_hash = hashTool.GetBytes(24);
			_salt = hashTool.Salt;
			IterationCount = hashTool.IterationCount;
		}

		public override string ToString()
		{
			return $"{IterationCount.ToString()}:{Convert.ToBase64String(GetSalt())}:{Convert.ToBase64String(GetHash())}";
		}
	}
}