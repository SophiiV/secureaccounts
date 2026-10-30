using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SecureAccounts.Services;

/// <summary>
/// Хешування паролів функцією PBKDF2-HMAC-SHA256 з випадковою сіллю.
/// Формат рядка в БД: PBKDF2-SHA256$ітерації$сіль(Base64)$хеш(Base64).
/// Під час входу хеш обчислюється заново з тією самою сіллю і кількістю ітерацій
/// і порівнюється зі збереженим за сталий час.
/// </summary>
public class PasswordHasher(IOptions<SecurityOptions> options)
{
    private const string Prefix = "PBKDF2-SHA256";
    private const int SaltSize = 16;   // 128 біт
    private const int HashSize = 32;   // 256 біт
    private readonly int _iterations = options.Value.Pbkdf2Iterations;
    private readonly Lazy<string> _dummy = new(() => new PasswordHasher(options).Hash("dummy-password"));

    public string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, _iterations,
            HashAlgorithmName.SHA256, HashSize);
        return $"{Prefix}${_iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string stored)
    {
        string[] parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix || !int.TryParse(parts[1], out int iterations))
            return false;
        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] expected = Convert.FromBase64String(parts[3]);
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations,
            HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Обчислення для неіснуючого користувача, щоб час відповіді не видавав, чи є такий email.</summary>
    public void DummyVerify(string password) => Verify(password, _dummy.Value);
}
