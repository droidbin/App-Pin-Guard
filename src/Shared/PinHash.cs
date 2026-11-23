using System;
using System.Security.Cryptography;

// PBKDF2-SHA256 PIN hashing. This is the only implementation in the repository.
internal static class PinHash
{
    private const int SaltLength = 16;
    private const int HashLength = 32;

    internal static PinRecord Create(string pin)
    {
        byte[] salt = new byte[SaltLength];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(salt);
        byte[] hash = Derive(pin, salt, PinRecord.DefaultIterations);
        return new PinRecord
        {
            Salt = Convert.ToBase64String(salt),
            Hash = Convert.ToBase64String(hash),
            Iterations = PinRecord.DefaultIterations,
            Version = DateTime.UtcNow.Ticks,
        };
    }

    internal static bool Verify(string pin, PinRecord record)
    {
        if (string.IsNullOrWhiteSpace(pin) || record == null || !record.IsSet) return false;
        try
        {
            byte[] salt = Convert.FromBase64String(record.Salt);
            byte[] expected = Convert.FromBase64String(record.Hash);
            if (salt.Length != SaltLength || expected.Length != HashLength) return false;
            int iterations = record.Iterations > 0 ? record.Iterations : PinRecord.DefaultIterations;
            byte[] actual = Derive(pin, salt, iterations);
            int difference = 0;
            for (int i = 0; i < expected.Length; i++) difference |= actual[i] ^ expected[i];
            return difference == 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool IsValid(PinRecord record)
    {
        if (record == null) return false;
        if (string.IsNullOrEmpty(record.Salt) && string.IsNullOrEmpty(record.Hash)) return true;
        try
        {
            return Convert.FromBase64String(record.Salt).Length == SaltLength &&
                Convert.FromBase64String(record.Hash).Length == HashLength;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] Derive(string pin, byte[] salt, int iterations)
    {
        using (var derivation = new Rfc2898DeriveBytes(pin, salt, iterations, HashAlgorithmName.SHA256))
            return derivation.GetBytes(HashLength);
    }
}
