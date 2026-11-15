namespace Kuznechik;

/// <summary>
/// "Kuznichik" symmetrical encryption algorithm, as defined in GOST-R 34.12-2015
/// </summary>
internal class BlockCipher
{
    /// <summary>
    /// The size of blocks the algorithm operates on.
    /// </summary>
    public const int BlockSize = 16;
    
    /// <summary>
    /// The size of the key used in the algorithm.
    /// </summary>
    public const int KeySize = BlockSize * 2;
    
    private const int RoundCount = 10;
    private const int RoundKeyExpandCount = 4;
    private const int FeistelIterCount = 8;

    private static readonly byte[] NonLinearTable =
    [
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
        0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
        0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
        0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
        0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
        0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
        0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
        0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
        0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
        0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
        0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
        0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
        0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
        0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
        0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    ];

    private static readonly byte[] NonLinearInverseTable =
    [
        0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
        0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
        0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
        0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
        0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
        0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
        0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
        0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
        0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
        0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
        0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
        0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
        0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
        0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
        0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
        0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
        0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
        0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
        0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
        0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
        0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
        0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
        0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
        0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
        0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
        0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
        0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
        0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
        0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
        0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
        0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
    ];

    private static readonly byte[] LinearTable =
    [
        148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
    ];

    private readonly byte[] _roundKeys;

    /// <summary>
    /// Initializes a new instance of <see cref="BlockCipher"/> with the specified key.
    /// </summary>
    /// <param name="key">The key used for encryption and decryption. The length of the key must be equal to 32.</param>
    /// <exception cref="ArgumentException">The key has incorrect length.</exception>
    public BlockCipher(ReadOnlySpan<byte> key)
    {
        _roundKeys = new byte[BlockSize * RoundCount];
        SetKey(key);
    }

    /// <summary>
    /// Sets the key used by the current instance of <see cref="BlockCipher"/>.
    /// </summary>
    /// <param name="key">The key used for encryption and decryption. The length of the key must be equal to 32.</param>
    /// <exception cref="ArgumentException">The key has incorrect length.</exception>
    public void SetKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be of length {KeySize}");
        }

        Span<byte> keyA = stackalloc byte[BlockSize];
        Span<byte> keyB = stackalloc byte[BlockSize];
        Span<byte> roundConstant = stackalloc byte[BlockSize];

        key[..BlockSize].CopyTo(keyA);
        key[BlockSize..].CopyTo(keyB);

        keyA.CopyTo(_roundKeys.AsSpan()[..BlockSize]);
        keyB.CopyTo(_roundKeys.AsSpan()[BlockSize..(BlockSize * 2)]);
        for (int i = 0; i < RoundKeyExpandCount; i++)
        {
            for (int j = 0; j < FeistelIterCount; j++)
            {
                roundConstant.Clear();
                roundConstant[^1] = (byte)(i * FeistelIterCount + j + 1);
                LinearTransform(roundConstant, roundConstant);

                FeistelTransform(keyA, keyB, roundConstant);
            }

            keyA.CopyTo(_roundKeys.AsSpan()[((i * 2 + 2) * BlockSize)..((i * 2 + 3) * BlockSize)]);
            keyB.CopyTo(_roundKeys.AsSpan()[((i * 2 + 3) * BlockSize)..((i * 2 + 4) * BlockSize)]);
        }
    }

    /// <summary>
    /// Encrypts a single block of plaintext.
    /// </summary>
    /// <param name="plainTextBlock">The original plaintext block, length 16.</param>
    /// <param name="cipherTextBlock">Where to write the ciphertext, length 16.</param>
    /// <exception cref="ArgumentException">Either parameter has incorrect length.</exception>
    public void EncryptBlock(ReadOnlySpan<byte> plainTextBlock, Span<byte> cipherTextBlock)
    {
        if (plainTextBlock.Length != BlockSize || cipherTextBlock.Length != BlockSize)
        {
            throw new ArgumentException($"Input and output blocks must be of length {BlockSize}");
        }

        plainTextBlock.CopyTo(cipherTextBlock);
        for (int i = 0; i < RoundCount - 1; i++)
        {
            Span<byte> roundKey = _roundKeys.AsSpan()[(i * BlockSize)..((i + 1) * BlockSize)];
            Xor(cipherTextBlock, roundKey, cipherTextBlock);
            NonLinearTransform(cipherTextBlock, cipherTextBlock);
            LinearTransform(cipherTextBlock, cipherTextBlock);
        }
        Span<byte> lastKey = _roundKeys.AsSpan()[((RoundCount - 1) * BlockSize)..(RoundCount * BlockSize)];
        Xor(cipherTextBlock, lastKey, cipherTextBlock);
    }
    
    /// <summary>
    /// Decrypts a single block of ciphertext.
    /// </summary>
    /// <param name="plainTextBlock">The ciphertext block, length 16.</param>
    /// <param name="cipherTextBlock">Where to write the plaintext, length 16.</param>
    /// <exception cref="ArgumentException">Either parameter has incorrect length.</exception>
    public void DecryptBlock(ReadOnlySpan<byte> cipherTextBlock, Span<byte> plainTextBlock)
    {
        if (plainTextBlock.Length != BlockSize || cipherTextBlock.Length != BlockSize)
        {
            throw new ArgumentException($"Input and output blocks must be of length {BlockSize}");
        }

        cipherTextBlock.CopyTo(plainTextBlock);
        Span<byte> lastKey = _roundKeys.AsSpan()[((RoundCount - 1) * BlockSize)..(RoundCount * BlockSize)];
        Xor(plainTextBlock, lastKey, plainTextBlock);
        for (int i = RoundCount - 2; i >= 0; i--)
        {
            LinearInverseTransform(plainTextBlock, plainTextBlock);
            NonLinearInverseTransform(plainTextBlock, plainTextBlock);
            Span<byte> roundKey = _roundKeys.AsSpan()[(i * BlockSize)..((i + 1) * BlockSize)];
            Xor(plainTextBlock, roundKey, plainTextBlock);
        }
    }

    /// <summary>
    /// Encrypts a single block of plaintext.
    /// </summary>
    /// <param name="plainTextBlock">The original plaintext block, length 16.</param>
    /// <exception cref="ArgumentException">The plaintext block has incorrect length.</exception>
    /// <returns>The ciphertext block.</returns>
    public byte[] EncryptBlock(ReadOnlySpan<byte> plainTextBlock)
    {
        if (plainTextBlock.Length != BlockSize)
        {
            throw new ArgumentException($"Input block must be of length {BlockSize}");
        }

        byte[] result = new byte[BlockSize];
        EncryptBlock(plainTextBlock, result);
        return result;
    }
    
    /// <summary>
    /// Decrypts a single block of ciphertext.
    /// </summary>
    /// <param name="cipherTextBlock">The ciphertext block, length 16.</param>
    /// <exception cref="ArgumentException">The ciphertext block has incorrect length.</exception>
    /// <returns>The plaintext block.</returns>
    public byte[] DecryptBlock(ReadOnlySpan<byte> cipherTextBlock)
    {
        if (cipherTextBlock.Length != BlockSize)
        {
            throw new ArgumentException($"Input block must be of length {BlockSize}");
        }

        byte[] result = new byte[BlockSize];
        DecryptBlock(cipherTextBlock, result);
        return result;
    }

    private static void FeistelTransform(Span<byte> keyA, Span<byte> keyB, ReadOnlySpan<byte> constant)
    {
        Span<byte> temp = stackalloc byte[16];
        Xor(keyA, constant, temp);
        NonLinearTransform(temp, temp);
        LinearTransform(temp, temp);
        Xor(temp, keyB, temp);
        keyA.CopyTo(keyB);
        temp.CopyTo(keyA);
    }

    private static void LinearTransform(ReadOnlySpan<byte> input, Span<byte> result)
    {
        input.CopyTo(result);
        for (int round = 0; round < BlockSize; round++)
        {
            byte firstByte = 0;
            for (int i = 0; i < BlockSize; i++)
            {
                firstByte ^= GaloisMul(result[i], LinearTable[i]);
            }
            
            for (int i = BlockSize - 1; i > 0; i--)
            {
                result[i] = result[i - 1];
            }


            result[0] = firstByte;
        }
    }

    private static void LinearInverseTransform(ReadOnlySpan<byte> input, Span<byte> result)
    {
        input.CopyTo(result);
        for (int round = 0; round < BlockSize; round++)
        {
            byte lastByte = result[0];
            for (int i = 0; i < BlockSize - 1; i++)
            {
                lastByte ^= GaloisMul(result[i + 1], LinearTable[i]);
            }

            for (int i = 0; i < BlockSize - 1; i++)
            {
                result[i] = result[i + 1];
            }

            result[^1] = lastByte;
        }
    }

    private static byte GaloisMul(byte a, byte b)
    {
        byte c = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
            {
                c ^= a;
            }

            bool highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet)
            {
                a ^= 0xC3;
            }

            b >>= 1;
        }

        return c;
    }

    private static void NonLinearTransform(ReadOnlySpan<byte> input, Span<byte> result)
    {
        for (int i = 0; i < BlockSize; i++)
        {
            result[i] = NonLinearTable[input[i]];
        }
    }

    private static void NonLinearInverseTransform(ReadOnlySpan<byte> input, Span<byte> result)
    {
        for (int i = 0; i < BlockSize; i++)
        {
            result[i] = NonLinearInverseTable[input[i]];
        }
    }

    private static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BitConverter.TryWriteBytes(result, BitConverter.ToUInt128(a) ^ BitConverter.ToUInt128(b));
    }
}