using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Keccak.Sha3;

public class Sha3
{
    private const int StateSizeBytes = 1600 / 8;
    private static readonly int[] RhoRotAmounts =
    [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
        25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    ];
    private static readonly ulong[] IotaConstants =
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ];
    private const byte PaddingStart = 0x06;
    private const byte PaddingEnd = 0x80;

    private readonly int _rateBytes;
    private readonly int _hashSizeBytes;

    private readonly byte[] _state;
    private readonly byte[] _addBuffer;
    private int _addPosition;

    /// <summary>
    /// Initializes an instance of the SHA3 algorithm with the specified hash size.
    /// </summary>
    /// <param name="outputSize">The size of the hash in bits, a multiple of 32.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputSize"/> is not positive,
    /// or is greater than or equal to 800.</exception>
    /// <exception cref="ArgumentException"><paramref name="outputSize"/> is not a multiple of 32.</exception>
    public Sha3(int outputSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(outputSize, 0);
        // Rate is defined as 1600 - 2*size, make sure that is it positive (i.e. size is < 800).
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(outputSize, 800);
        if (outputSize % 32 != 0)
        {
            // We do word-wise math (w=64), so rate (which is defined as 1600 - 2*size) needs to be
            // a multiple of 64 for AbsorbChunk to work properly, thus size needs to be a multiple of 32.
            throw new ArgumentException("Output size must be a multiple of 32.");
        }

        _rateBytes = StateSizeBytes - outputSize / 4;
        _hashSizeBytes = outputSize / 8;

        _state = new byte[StateSizeBytes];
        _addBuffer = new byte[_rateBytes];
        _addPosition = 0;
    }

    /// <summary>
    /// Adds a chunk of data to the hasher's internal state.
    /// </summary>
    /// <param name="input">The data to add.</param>
    public void Add(ReadOnlySpan<byte> input)
    {
        while (input.Length > 0)
        {
            int bytesToAdd = int.Min(input.Length, _rateBytes - _addPosition);
            input[..bytesToAdd].CopyTo(_addBuffer.AsSpan()[_addPosition..]);
            _addPosition += bytesToAdd;
            input = input[bytesToAdd..];

            if (_addPosition == _rateBytes)
            {
                AbsorbChunk();
            }
        }
    }

    /// <summary>
    /// Computes the final hash. Should be called after <see cref="Add"/>.
    /// Resets the state of the hasher, so a new hash can be computed with the same hasher.
    /// </summary>
    /// <param name="output">The output buffer to write the hash to.</param>
    /// <exception cref="ArgumentException">Output buffer size does not match hash size.</exception>
    public void Compute(Span<byte> output)
    {
        if (output.Length != _hashSizeBytes)
        {
            // Make sure that the buffer has exactly the same size as the size of the hash
            // so that the user does not accidentally truncate the hash or get a non-standard extended hash.
            throw new ArgumentException("Output buffer size does not match hash size.");
        }
        
        _addBuffer.AsSpan()[_addPosition..].Clear();
        _addBuffer[_addPosition] |= PaddingStart;
        _addBuffer[^1] |= PaddingEnd;
        AbsorbChunk();

        while (output.Length > 0)
        {
            int bytesToOutput = int.Min(output.Length, _rateBytes);
            _state.AsSpan(0, bytesToOutput).CopyTo(output);
            output = output[bytesToOutput..];
            if (output.Length > 0)
            {
                Permute();
            }
        }
        
        Reset();
    }

    /// <summary>
    /// Computes the final hash. Should be called after <see cref="Add"/>.
    /// Resets the state of the hasher, so a new hash can be computed with the same hasher.
    /// </summary>
    /// <returns>The hash value.</returns>
    public byte[] Compute()
    {
        byte[] result = new byte[_hashSizeBytes];
        Compute(result);
        return result;
    }

    /// <summary>
    /// Computes the hash of the specified input, discarding the previous state.
    /// </summary>
    /// <param name="output">The output buffer to write the hash to.</param>
    /// <param name="input">The data to hash.</param>
    /// <exception cref="ArgumentException">Output buffer size does not match hash size.</exception>
    public void ComputeAll(Span<byte> output, ReadOnlySpan<byte> input)
    {
        Reset();
        Add(input);
        Compute(output);
    }

    /// <summary>
    /// Computes the hash of the specified input, discarding the previous state.
    /// </summary>
    /// <param name="input">The data to hash.</param>
    /// <returns>The hash value.</returns>
    public byte[] ComputeAll(ReadOnlySpan<byte> input)
    {
        byte[] result = new byte[_hashSizeBytes];
        ComputeAll(result, input);
        return result;
    }

    /// <summary>
    /// Resets the state of the hasher as if nothing was added to it.
    /// </summary>
    private void Reset()
    {
        _state.AsSpan().Clear();
        _addPosition = 0;
    }

    /// <summary>
    /// Absorbs the chunk stored in <see cref="_addBuffer"/> into the sponge,
    /// XOR-ring it with the "visible" part of the sponge and performing a permutation.
    /// Also resets <see cref="_addPosition"/> to 0.
    /// </summary>
    private void AbsorbChunk()
    {
        _addPosition = 0;

        // Word-wise XOR-ring for better performance.
        Span<ulong> stateWords = MemoryMarshal.Cast<byte, ulong>(_state.AsSpan());
        ReadOnlySpan<ulong> addWords = MemoryMarshal.Cast<byte, ulong>(_addBuffer.AsSpan());
        for (int i = 0; i < addWords.Length; i++)
        {
            stateWords[i] ^= addWords[i];
        }

        Permute();
    }

    /// <summary>
    /// Performs a full 24-round permutation.
    /// </summary>
    private void Permute()
    {
        for (int i = 0; i < 24; i++)
        {
            PermuteRound(i);
        }
    }

    /// <summary>
    /// Performs a single permutation round, consisting of the theta, rho, pi, chi and iota steps.
    /// </summary>
    /// <param name="permutationIndex">The permutation index for the iota step.</param>
    private void PermuteRound(int permutationIndex)
    {
        // Word-wise maths for better performance.
        Span<ulong> stateWords = MemoryMarshal.Cast<byte, ulong>(_state.AsSpan());

        // theta
        Span<ulong> parity = stackalloc ulong[5];
        for (int i = 0; i < 5; i++)
        {
            for (int j = 0; j < 5; j++)
            {
                parity[i] ^= stateWords[i + 5 * j];
            }
        }
        for (int i = 0; i < 5; i++)
        {
            for (int j = 0; j < 5; j++)
            {
                ulong parity1 = parity[(i + 4) % 5];
                ulong parity2 = parity[(i + 1) % 5];
                stateWords[i + 5 * j] ^= parity1 ^ RotateLeft(parity2, 1);
            }
        }

        // rho
        for (int i = 0; i < 25; i++)
        {
            stateWords[i] = RotateLeft(stateWords[i], RhoRotAmounts[i]);
        }

        // pi
        Span<ulong> piBuffer = stackalloc ulong[25];
        for (int i = 0; i < 5; i++)
        {
            for (int j = 0; j < 5; j++)
            {
                piBuffer[i + 5 * j] = stateWords[(i + 3 * j) % 5 + 5 * i];
            }
        }

        // chi
        for (int i = 0; i < 5; i++)
        {
            for (int j = 0; j < 5; j++)
            {
                int i1 = (i + 1) % 5;
                int i2 = (i + 2) % 5;
                stateWords[i + 5 * j] = piBuffer[i + 5 * j] ^ (~piBuffer[i1 + 5 * j] & piBuffer[i2 + 5 * j]);
            }
        }

        // iota
        ulong iotaConstant = IotaConstants[permutationIndex];
        if (!BitConverter.IsLittleEndian)
        {
            // Reverse the byte order of the constant if the host is big-endian, because 
            // on a big-endian platform the constants would be stored as big-endian integers,
            // and SHA3 requires the bytes of the constants in little-endian order.
            iotaConstant = BinaryPrimitives.ReverseEndianness(iotaConstant);
        }
        stateWords[0] ^= iotaConstant;
    }

    /// <summary>
    /// Bit-rotates a 64-bit word left in little-endian byte order.
    /// </summary>
    /// <param name="word">The word to rotate.</param>
    /// <param name="amount">The rotation amount.</param>
    /// <returns>The rotated word.</returns>
    private static ulong RotateLeft(ulong word, int amount)
    {
        // The standard SHA3 assumes little-endian byte order.
        // If the machine is big-endian a regular bit-rotate would produce unexpected results.
        // Reverse the byte order of the word if the host is big-endian.
        if (!BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
        }
        word = BitOperations.RotateLeft(word, amount);
        // Reverse the rotated word back to big-endian order.
        if (!BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
        }
        return word;
    }
}
