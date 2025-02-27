using System.Text;
using System.Security.Cryptography;
using System.Text;

namespace GestionDeUsuarioAPI.Services
{
    public class Encriptar
    {
    // encripto la contraseña con SHA-256
    public static string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            // Converto la contraseña
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // genero el hash de la contra
            byte[] hashBytes = sha256.ComputeHash(passwordBytes);

            // hash pasa a como cadena a base 64 
            return Convert.ToBase64String(hashBytes);
        }
    }

    // verifico si la contraseña ingresada coincide con la  almacenada
    public static bool VerifyPassword(string enteredPassword, string storedPasswordHash)
    {
        // Encripto la contraseña 
        string enteredPasswordHash = HashPassword(enteredPassword);

        return enteredPasswordHash == storedPasswordHash;
    }
    }
}
