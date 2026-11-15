namespace Keccak.Sha3;

internal static class Program
{
    private const int BufferSize = 4096;
    
    private static int Main()
    {
        try
        {
            Sha3 sha3 = new Sha3(256);
            
            Stream input = Console.OpenStandardInput();
            byte[] buffer = new byte[BufferSize];
            int bytesRead;

            while ((bytesRead = input.Read(buffer.AsSpan())) > 0)
            {
                sha3.Add(buffer.AsSpan()[..bytesRead]);
            }
            
            byte[] hash = sha3.Compute();
            string hex = Convert.ToHexStringLower(hash);
            Console.WriteLine(hex);
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("Error: " + e);
            return 1;
        }
    }
}
