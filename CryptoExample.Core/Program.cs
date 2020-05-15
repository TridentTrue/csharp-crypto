using System;
using System.Diagnostics;
using System.IO;
using NIHE.Cryptography;

namespace CryptoExample
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			if (args.Length == 0)
			{
				Console.WriteLine("No command line arguments supplied. Exiting...");
				return;
			}

			if (args[0] == "--validate" || args[0] == "-v")
			{
				// in a real application we will read the stored password from a database
				string storedPassword = File.ReadAllText(Directory.GetCurrentDirectory() + @"\store.txt");
				string passwordToTest = args[Array.IndexOf(args, "-validate") + 1];

				bool isPasswordValid = Vault.ValidatePassword(passwordToTest, storedPassword);
				Console.WriteLine(isPasswordValid ? "Access Granted" : "Access Denied");
			}
			else
			{
				// get password from user input
				string suppliedPlaintext = args[0];

				// Generate password hash
				Console.WriteLine("Generating secure password...");
				Stopwatch hashStopwatch = Stopwatch.StartNew();
				SecurePassword myPassword = new SecurePassword(suppliedPlaintext);
				hashStopwatch.Stop();
				Console.WriteLine($"Using salt '{Convert.ToBase64String(myPassword.GetSalt())}'");
				Console.WriteLine($"Hash is '{Convert.ToBase64String(myPassword.GetHash())}'");
				Console.WriteLine($"Process took {hashStopwatch.Elapsed.TotalSeconds} secs");

				// verify that password is secure
				Console.WriteLine("Verifying hash...");
				Stopwatch verificationStopwatch = Stopwatch.StartNew();
				bool isVerified = Vault.VerifyHash(suppliedPlaintext, myPassword);
				verificationStopwatch.Stop();
				Console.WriteLine(isVerified ? "Success!" : "Failed!");
				Console.WriteLine($"Process took {verificationStopwatch.Elapsed.TotalSeconds} secs");

				string passwordStringToStore = myPassword.ToString();
				// in a real application this will be written to the database rather than a .txt
				File.WriteAllText(Directory.GetCurrentDirectory() + @"\store.txt", passwordStringToStore);
				Console.WriteLine($"Password hashed as: {passwordStringToStore}");
				double totalTimeTaken = hashStopwatch.Elapsed.TotalSeconds + verificationStopwatch.Elapsed.TotalSeconds;
				Console.WriteLine($"Total time taken: {totalTimeTaken} secs");
			}
		}
	}
}