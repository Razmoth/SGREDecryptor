// C# port of https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.c

namespace SGREDecryptor;

public class MT19937
{
    private const int N = 624;
    private const int M = 397;
    private const uint MATRIX_A = 0x9908B0DF;
    private const uint UPPER_MASK = 0x80000000;
    private const uint LOWER_MASK = 0X7FFFFFFF;

    private readonly uint[] mt = new uint[N + 1];
    private int mti = N + 1;

    public MT19937(uint seed)
    {
        Init(seed);
    }

    public MT19937(ReadOnlySpan<uint> seed)
    {
        int i = 1, j = 0, k;

        Init(0x12BD6AA);

        for (k = Math.Max(seed.Length, N) ; k > 0; k--)
        {
            mt[i] = (uint)((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 0x19660D))
              + seed[j] + j);
            i++; j++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
            if (j >= seed.Length) j = 0;
        }

        for (k = N - 1; k > 0; k--)
        {
            mt[i] = (uint)((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 0x5D588B65)) - i);
            i++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
        }

        mt[0] = 0x80000000;
    }

    private void Init(uint seed)
    {
        mt[0] = seed;
        for (mti = 1; mti < N; mti++)
        {
            mt[mti] = (uint)(0x6C078965 * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti);
        }
    }

    public uint UInt32()
    {
        uint y;
        Span<uint> mag01 = [ 0, MATRIX_A ];

        if (mti >= N)
        {
            int kk;

            if (mti == N + 1)
            {
                Init(0x1571);
            }
            
            for (kk = 0; kk < (N - M); kk++)
            {
                y = mt[kk] & UPPER_MASK | mt[kk + 1] & LOWER_MASK;
                mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[(int)(y & 1)];
            }

            for (; kk < N - 1; kk++)
            {
                y = mt[kk] & UPPER_MASK | mt[kk + 1] & LOWER_MASK;
                mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[(int)(y & 0x1)];
            }

            y = mt[N - 1] & UPPER_MASK | mt[0] & LOWER_MASK;
            mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[(int)(y & 0x1)];

            mti = 0;
        }

        y = mt[mti++];
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C5680;
        y ^= (y << 15) & 0xEFC60000;
        y ^= y >> 18;
        return y;
    }
}