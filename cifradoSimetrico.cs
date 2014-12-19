// Programa para cifrar o descifrar pequeños textos planos con algoritmos simétricos (AES, DES, Rijndael)
// J. Cristóbal López Zafra, @JCristobal en GitHub

// Código basado en CipherUtility.cs de http://www.superstarcoders.com/blogs/posts/symmetric-encryption-in-c-sharp.aspx , modificado por J. Cristóbal López Zafra, para la asignatura SPSI, entrega 2: Algoritmos simétricos, de ETSIIT (Granada, España)

using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

public class CipherUtility
{
	public static string Encrypt<T>(string value, string password, string salt)
		  where T : SymmetricAlgorithm, new()
	{
		DeriveBytes rgb = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

		SymmetricAlgorithm algorithm = new T();

		byte[] rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
		byte[] rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

		ICryptoTransform transform = algorithm.CreateEncryptor(rgbKey, rgbIV);

		using (MemoryStream buffer = new MemoryStream())
		{
			using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
			{
				using (StreamWriter writer = new StreamWriter(stream, Encoding.Unicode))
				{
					writer.Write(value);
				}
			}

			return Convert.ToBase64String(buffer.ToArray());
		}
	}

	public static string Decrypt<T>(string text, string password, string salt)
	   where T : SymmetricAlgorithm, new()
	{
		DeriveBytes rgb = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

		SymmetricAlgorithm algorithm = new T();

		byte[] rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
		byte[] rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

		ICryptoTransform transform = algorithm.CreateDecryptor(rgbKey, rgbIV);

		using (MemoryStream buffer = new MemoryStream(Convert.FromBase64String(text)))
		{
			using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Read))
			{
				using (StreamReader reader = new StreamReader(stream, Encoding.Unicode))
				{
					return reader.ReadToEnd();
				}
			}
		}
	}

       // Generate a simple yet strong salt key.  Only alphas in this example, but you can pimp the example easily.
       // Use the RNGCryptoServiceProvider to get random bytes. So should be reasonably random
       //
       // name="maxSize">How much NaCl is required ?
       // returns Random alpha string you can use as SALT
       public static string GenerateSimpleSalt(int maxSize = 64)
       {
           var alphaSet = new char[64]; // use 62 for strict alpha... that random generator for alphas only
           //nicer results with set length * int i = 256. But still produces excellent random results.
           //alphaset plus 2.  Reduce to 62 if alpha requried
           alphaSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890#!".ToCharArray();
           var crypto = new RNGCryptoServiceProvider();
           var bytes = new byte[maxSize];
           crypto.GetBytes(bytes); //get a bucket of very random bytes
           var tempSB = new StringBuilder(maxSize);
           foreach (var b in bytes)
           {   // use b , a random from 0-255 as the index to our source array. Just mod on length set
               tempSB.Append(alphaSet[b % (alphaSet.Length)]);
           }
           return tempSB.ToString();
       }


public static void Main(string[] args){


	string plain = "", password, encrypted="", decrypted="", caseSwitch = "", mode="", modo_salt="", salt="salt";

	Console.WriteLine("Escribe 'c' para cifrar y 'd' para descifrar: ");
	mode = Console.ReadLine () ;

	if(mode=="c"){
		Console.WriteLine("Escribe el texto para cifrar: ");
		plain = Console.ReadLine () ;

		Console.WriteLine("Y escribe la contraseña: ");
		password = Console.ReadLine () ;

		Console.WriteLine("Elige el modo para cifrar, a para AES, b para DES, c para Rijndael: ");
		caseSwitch = Console.ReadLine () ;

		Console.WriteLine("Si quieres una llave 'salt' fuerte pulsa 'x' (pero después no podrás descifrarlo): ");
		modo_salt = Console.ReadLine () ;

		if(modo_salt=="x"){
			salt=GenerateSimpleSalt();
		}

		switch (caseSwitch){

		    case "a":  //AES
		
			encrypted = CipherUtility.Encrypt<AesManaged>(plain, password, salt);

			break;

		    case "b":  //DES
	
			encrypted = CipherUtility.Encrypt<TripleDESCryptoServiceProvider>(plain, password, salt);

			break;

		    case "c":  //Rijndael
	
			encrypted = CipherUtility.Encrypt<RijndaelManaged>(plain, password, salt);

			break;
		}

		Console.WriteLine("\nTu texto encriptado: ");
		Console.WriteLine(encrypted);
	}
	else if(mode=="d"){

		Console.WriteLine("Escribe el texto para descifrar: ");
		plain = Console.ReadLine () ;

		Console.WriteLine("Y escribe la contraseña: ");
		password = Console.ReadLine () ;

		Console.WriteLine("Elige el modo para descifrar, a para AES, b para DES, c para Rijndael: ");
		caseSwitch = Console.ReadLine () ;

		switch (caseSwitch){

		    case "a":  //AES
		
			decrypted = CipherUtility.Decrypt<AesManaged>(plain, password, salt);

			break;

		    case "b":  //DES
	
			decrypted = CipherUtility.Decrypt<TripleDESCryptoServiceProvider>(plain, password, salt);

			break;

		    case "c":  //Rijndael
	
			decrypted = CipherUtility.Decrypt<RijndaelManaged>(plain, password, salt);

			break;
		}

		Console.WriteLine("\nTu texto desencriptado: ");
		Console.WriteLine(decrypted);
	}
	else{
		Console.WriteLine("\nIntroduce la opción correcta ");
	}



}

}

