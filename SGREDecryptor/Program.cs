using SGREDecryptor;
using System.CommandLine;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

Argument<DirectoryInfo> folderArgument = new("folder");

folderArgument.AcceptLegalFilePathsOnly();

RootCommand rootCommand = new("SGREDecryptor")
{
    folderArgument,
};

rootCommand.SetAction(Parse);
return rootCommand.Parse(args).Invoke();

void Parse(ParseResult result)
{
    DirectoryInfo dir = result.GetRequiredValue(folderArgument);

    Main(dir);
}

void Main(DirectoryInfo dir)
{
    foreach (FileInfo file in dir.EnumerateFiles("*.m"))
    {
        try
        {
            Decrypt(file);
            Console.WriteLine($"Decrypted {file.Name} !!");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Unable to decrypt {file.Name}: {e.Message}");
        }
    }
}

void Decrypt(FileInfo file)
{
    Console.WriteLine($"File: {file.FullName}");

    if (file.Length < 8)
    {
        throw new InvalidDataException("File too small !!");
    }

    using Stream stream = file.OpenRead();
    using BinaryReader reader = new(stream);

    int signature = reader.ReadInt32();
    Console.WriteLine($"Signature: 0x{signature:X8}");

    if (signature != 0x737A6D) // mzs
    {
        throw new InvalidDataException("Not a valid mzs signature !!");
    }

    int decompressedSize = reader.ReadInt32();
    Console.WriteLine($"DecompressedSize: 0x{decompressedSize:X8}");

    long size = stream.Length - stream.Position;
    Console.WriteLine($"Size: 0x{size:X16}");

    Span<byte> seed = stackalloc byte[16];
    ReadOnlySpan<byte> prefix = "Rk3nwA8ZYV0yV"u8;
    ReadOnlySpan<byte> name = Encoding.UTF8.GetBytes(file.Name);

    if (name.Length > 0x100)
    {
        throw new Exception("File name too long !!");
    }

    Span<byte> buffer = stackalloc byte[prefix.Length + file.Name.Length];

    prefix.CopyTo(buffer);
    name.CopyTo(buffer[prefix.Length..]);

    int n = MD5.HashData(buffer, seed);
    if (n != seed.Length)
    {
        throw new InvalidDataException("Seed size mismatch !!");
    }

    Console.WriteLine($"Seed: {Convert.ToHexString(seed)}");

    ReadOnlySpan<uint> seedUints = MemoryMarshal.Cast<byte, uint>(seed);

    MT19937 mt = new(seedUints);

    int blockSize = 0x83;
    Span<byte> xorpad = stackalloc byte[blockSize];
    Span<byte> next = stackalloc byte[4];
    Span<uint> nextUints = MemoryMarshal.Cast<byte, uint>(next);

    for (int i = 0; i < xorpad.Length; i++)
    {
        if (i % next.Length == 0)
        {
            nextUints[0] = mt.UInt32();
        }

        xorpad[i] = next[i % next.Length];
    }

    using MemoryStream ms = new();

    Span<byte> block = stackalloc byte[blockSize];

    long remaining = size;
    while (remaining > 0)
    {
        int count = (int)Math.Min(remaining, blockSize);

        stream.ReadExactly(block[..count]);

        for (int i = 0; i < count; i++)
        {
            block[i] ^= xorpad[i];
        }

        ms.Write(block[..count]);

        remaining -= count;
    }

    ms.Position = 0;

    using ZstandardStream zstdStream = new(ms, CompressionMode.Decompress);
    using MemoryStream output = new();

    zstdStream.CopyTo(output);

    if (output.Length != decompressedSize)
    {
        throw new InvalidDataException("Decompressed size mismatch !!");
    }

    output.Position = 0;

    if (file.Directory != null)
    {
        DirectoryInfo outputDir = file.Directory.CreateSubdirectory("decrypted");
        string outputPath = Path.Combine(outputDir.FullName, file.Name);
        using FileStream outFile = File.OpenWrite(outputPath);
        output.CopyTo(outFile);
    }
}