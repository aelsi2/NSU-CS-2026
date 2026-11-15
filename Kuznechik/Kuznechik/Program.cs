using System.CommandLine;
using System.CommandLine.Parsing;

namespace Kuznechik;

internal static class Program
{
    private const byte Terminator = 0x80;
    
    private static int Main(string[] args)
    {
        RootCommand rootCommand = new RootCommand();

        Option<string> keyOption = new Option<string>("--key", "-K")
        {
            Description = "The encryption/decryption key in base64",
            Required = true
        };
        Option<FileInfo> inOption = new Option<FileInfo>("--input", "-i")
        {
            Description = "The path to the file to encrypt",
            Required = false
        };
        Option<FileInfo> outOption = new Option<FileInfo>("--output", "-o")
        {
            Description = "The output path",
            Required = false
        };

        Stream? OpenInput(ParseResult parseResult)
        {
            FileInfo? inFile = parseResult.GetValue(inOption);
            if (inFile != null)
            {
                try
                {
                    return inFile.Open(FileMode.Open, FileAccess.Read);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Could not open input file: " + e.Message);
                    return null;
                }
            }

            return Console.OpenStandardInput();
        }
        
        Stream? OpenOutput(ParseResult parseResult)
        {
            FileInfo? outFile = parseResult.GetValue(outOption);
            if (outFile != null)
            {
                try
                {
                    return outFile.Open(FileMode.OpenOrCreate, FileAccess.Write);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Could not open input file: " + e.Message);
                    return null;
                }
            }

            return Console.OpenStandardOutput();
        }
        
        Command encryptCommand = new Command("encrypt", "Encrypt a file");
        encryptCommand.SetAction(parseResult =>
        {
            byte[]? key = ParseKey(parseResult.GetRequiredValue(keyOption));
            if (key == null)
            {
                return 1;
            }

            using Stream? input = OpenInput(parseResult);
            using Stream? output = OpenOutput(parseResult);

            if (input == null || output == null)
            {
                return 1;
            }
            
            BlockCipher cipher = new BlockCipher(key);
            Encrypt(cipher, input, output);
            return 0;
        });
        
        Command decryptCommand = new Command("decrypt", "Decrypt a file");
        decryptCommand.SetAction(parseResult =>
        {
            byte[]? key = ParseKey(parseResult.GetRequiredValue(keyOption));
            if (key == null)
            {
                return 1;
            }
            
            using Stream? input = OpenInput(parseResult);
            using Stream? output = OpenOutput(parseResult);

            if (input == null || output == null)
            {
                return 1;
            }
            
            BlockCipher cipher = new BlockCipher(key);
            Decrypt(cipher, input, output);
            return 0;
        });

        encryptCommand.Add(keyOption);
        decryptCommand.Add(keyOption);
        encryptCommand.Add(inOption);
        decryptCommand.Add(inOption);
        encryptCommand.Add(outOption);
        decryptCommand.Add(outOption);
        rootCommand.Add(encryptCommand);
        rootCommand.Add(decryptCommand);

        ParseResult parseResult = rootCommand.Parse(args);
        if (parseResult.Errors.Count != 0)
        {
            foreach (ParseError parseError in parseResult.Errors)
            {
                Console.Error.WriteLine(parseError.Message);
            }

            return 1;
        }

        return parseResult.Invoke();
    }
    
    private static byte[]? ParseKey(string stringKey)
    {
        byte[] key = new byte[BlockCipher.KeySize];
        Convert.FromHexString(stringKey, key, out int consumed, out int written);
        if (consumed != stringKey.Length || written != key.Length)
        {
            Console.Error.WriteLine("Key must be a hex-encoded string of 32 bytes.");
            return null;
        }
        return key;
    }

    private static void Encrypt(BlockCipher cipher, Stream input, Stream output)
    {
        Span<byte> inBuffer = stackalloc byte[BlockCipher.BlockSize];
        Span<byte> outBuffer = stackalloc byte[BlockCipher.BlockSize];
        int bytesInBuffer = 0;
        int bytesRead;

        while ((bytesRead = input.Read(inBuffer[bytesInBuffer..])) > 0)
        {
            bytesInBuffer += bytesRead;
            if (bytesInBuffer == BlockCipher.BlockSize)
            {
                cipher.EncryptBlock(inBuffer, outBuffer);
                output.Write(outBuffer);
                bytesInBuffer = 0;
            }
        }

        inBuffer[bytesInBuffer..].Clear();
        inBuffer[bytesInBuffer] = Terminator;
        cipher.EncryptBlock(inBuffer, outBuffer);
        output.Write(outBuffer);
        output.Flush();
    }
    
    private static void Decrypt(BlockCipher cipher, Stream input, Stream output)
    {
        Span<byte> inBuffer = stackalloc byte[BlockCipher.BlockSize];
        Span<byte> outBuffer = stackalloc byte[BlockCipher.BlockSize];
        bool writePending = false;
        int bytesInBuffer = 0;
        int bytesRead;

        while ((bytesRead = input.Read(inBuffer[bytesInBuffer..])) > 0)
        {
            if (writePending)
            {
                output.Write(outBuffer);
                writePending = false;
            }
            bytesInBuffer += bytesRead;
            if (bytesInBuffer == BlockCipher.BlockSize)
            {
                cipher.DecryptBlock(inBuffer, outBuffer);
                bytesInBuffer = 0;
                writePending = true;
            }
        }
        
        if (writePending)
        {
            int terminatorIndex = outBuffer.LastIndexOf(Terminator);
            if (terminatorIndex == -1)
            {
                Console.Error.WriteLine("Warning: missing message terminator");
                output.Write(outBuffer);
            }
            else
            {
                output.Write(outBuffer[..terminatorIndex]);
            }
        }
        output.Flush();
    }
}