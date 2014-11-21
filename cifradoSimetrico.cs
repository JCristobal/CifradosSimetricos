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


public static void Main(string[] args){


	string plain = "", password, encrypted="", decrypted="", caseSwitch = "";

	Console.WriteLine("Escribe el texto para cifrar: ");
	plain = Console.ReadLine () ;

	Console.WriteLine("Y escribe la contraseña: ");
	password = Console.ReadLine () ;

	Console.WriteLine("Elige el modo para cifrar, a para AES, b para DES, c para Rijndael: ");
	caseSwitch = Console.ReadLine () ;

	switch (caseSwitch){

	    case "a":  //AES
		
		encrypted = CipherUtility.Encrypt<AesManaged>(plain, password, "salt");
		decrypted = CipherUtility.Decrypt<AesManaged>(encrypted, password, "salt");

		break;

	    case "b":  //DES
	
		encrypted = CipherUtility.Encrypt<TripleDESCryptoServiceProvider>(plain, password, "salt");
		decrypted = CipherUtility.Decrypt<TripleDESCryptoServiceProvider>(encrypted, password, "salt");

		break;

	    case "c":  //Rijndael
	
		encrypted = CipherUtility.Encrypt<RijndaelManaged>(plain, password, "salt");
		decrypted = CipherUtility.Decrypt<RijndaelManaged>(encrypted, password, "salt");

		break;
	}

	Console.WriteLine("\nTu texto encriptado: ");
	Console.WriteLine(encrypted);

	// Descomenta la siguiente linea si quieres que te devuelva el texto plano original, desencriptando el recien encriptado
	//Console.WriteLine("Comprobamos el texto, el texto para encriptar era: "+decrypted);


}

}

