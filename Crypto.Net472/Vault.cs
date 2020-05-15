using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace NIHE.Cryptography
{
	public static class Vault
	{
		public static byte[] CreateSalt()
		{
			RNGCryptoServiceProvider saltCellar = new RNGCryptoServiceProvider();
			byte[] salt = new byte[24];
			saltCellar.GetBytes(salt);
			return salt;
		}

		public static bool VerifyHash(string password, SecurePassword originalPassword)
		{
			SecurePassword newResult = new SecurePassword(password, originalPassword.GetSalt(), originalPassword.IterationCount);
			return SlowEquals(originalPassword.GetHash(), newResult.GetHash());
		}

		public static bool VerifyHash(string password, byte[] originalHash, byte[] salt, int iterationCount)
		{
			SecurePassword newResult = new SecurePassword(password, salt, iterationCount);
			return SlowEquals(originalHash, newResult.GetHash());
		}

		public static bool ValidatePassword(string testPassword, string storedPassword)
		{
			string[] originalHashParts = storedPassword.Split(':');
			int iterations = int.Parse(originalHashParts[0]);
			byte[] originalSalt = Convert.FromBase64String(originalHashParts[1]);
			byte[] originalHash = Convert.FromBase64String(originalHashParts[2]);

			return VerifyHash(testPassword, originalHash, originalSalt, iterations);
		}

		// See http://bryanavery.co.uk/cryptography-net-avoiding-timing-attack/ for general reasoning
		[MethodImpl(MethodImplOptions.NoOptimization)]
		private static bool SlowEquals(byte[] hashA, byte[] hashB)
		{
			uint differences = (uint)hashA.Length ^ (uint)hashB.Length;
			for (int i = 0; i < Math.Min(hashA.Length, hashB.Length); i++)
			{
				differences |= (uint)(hashA[i] ^ hashB[i]);
			}

			bool passwordMatches = differences == 0;
			return passwordMatches;
		}
	}
}
