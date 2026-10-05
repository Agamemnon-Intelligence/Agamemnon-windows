using System.Buffers.Binary;
using System.Text;

namespace Agamemnon.Core.Dns;

/// <summary>
/// Just enough DNS wire-format handling (RFC 1035) for forwarding queries and for the leak test.
/// Queries are forwarded verbatim; we only ever read the header and the first question.
/// </summary>
public static class DnsMessage
{
    public const int HeaderLength = 12;
    public const ushort TypeA = 1;
    public const ushort TypeTxt = 16;
    public const ushort TypeAaaa = 28;
    public const ushort ClassIn = 1;

    public static ushort ReadId(ReadOnlySpan<byte> message) => BinaryPrimitives.ReadUInt16BigEndian(message);

    public static void WriteId(Span<byte> message, ushort id) => BinaryPrimitives.WriteUInt16BigEndian(message, id);

    public static bool IsTruncated(ReadOnlySpan<byte> message) => message.Length >= 3 && (message[2] & 0x02) != 0;

    public static int ResponseCode(ReadOnlySpan<byte> message) => message.Length >= 4 ? message[3] & 0x0F : -1;

    /// <summary>Reads the first question. Returns false for anything malformed.</summary>
    public static bool TryReadQuestion(ReadOnlySpan<byte> message, out string name, out ushort type, out int questionEnd)
    {
        name = string.Empty;
        type = 0;
        questionEnd = 0;
        if (message.Length < HeaderLength || BinaryPrimitives.ReadUInt16BigEndian(message[4..]) == 0)
        {
            return false;
        }

        int offset = HeaderLength;
        if (!TryReadName(message, ref offset, out name, allowPointers: false) || offset + 4 > message.Length)
        {
            return false;
        }

        type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
        questionEnd = offset + 4;
        return true;
    }

    /// <summary>Builds a SERVFAIL answer to <paramref name="query"/> so clients fail fast instead of timing out.</summary>
    public static byte[] ServerFailure(ReadOnlySpan<byte> query)
    {
        int questionEnd = HeaderLength;
        bool hasQuestion = TryReadQuestion(query, out _, out _, out int end);
        if (hasQuestion)
        {
            questionEnd = end;
        }

        byte[] response = new byte[Math.Max(questionEnd, HeaderLength)];
        query[..Math.Min(query.Length, questionEnd)].CopyTo(response);
        response[2] = (byte)(0x80 | (query.Length > 2 ? query[2] & 0x79 : 0)); // QR=1, keep opcode and RD
        response[3] = 0x80 | 0x02; // RA=1, RCODE=SERVFAIL
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4), hasQuestion ? (ushort)1 : (ushort)0);
        response.AsSpan(6, 6).Clear(); // no answer, authority or additional records
        return response;
    }

    public static byte[] BuildQuery(string name, ushort type, ushort id)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        header[2] = 0x01; // RD
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        stream.Write(header);
        foreach (string label in name.TrimEnd('.').Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
            {
                throw new ArgumentException($"Invalid DNS name '{name}'.", nameof(name));
            }

            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(tail, type);
        BinaryPrimitives.WriteUInt16BigEndian(tail[2..], ClassIn);
        stream.Write(tail);
        return stream.ToArray();
    }

    /// <summary>Returns the character-strings of every TXT record in the answer section.</summary>
    public static IReadOnlyList<IReadOnlyList<string>> ReadTxtAnswers(ReadOnlySpan<byte> response)
    {
        var results = new List<IReadOnlyList<string>>();
        if (!TryReadQuestion(response, out _, out _, out int offset))
        {
            return results;
        }

        int answers = BinaryPrimitives.ReadUInt16BigEndian(response[6..]);
        for (int i = 0; i < answers; i++)
        {
            if (!TryReadName(response, ref offset, out _, allowPointers: true) || offset + 10 > response.Length)
            {
                break;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(response[offset..]);
            int rdLength = BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 8)..]);
            offset += 10;
            if (offset + rdLength > response.Length)
            {
                break;
            }

            if (type == TypeTxt)
            {
                var strings = new List<string>();
                int p = offset;
                while (p < offset + rdLength)
                {
                    int len = response[p++];
                    if (p + len > offset + rdLength)
                    {
                        break;
                    }

                    strings.Add(Encoding.UTF8.GetString(response.Slice(p, len)));
                    p += len;
                }

                results.Add(strings);
            }

            offset += rdLength;
        }

        return results;
    }

    private static bool TryReadName(ReadOnlySpan<byte> message, ref int offset, out string name, bool allowPointers)
    {
        var builder = new StringBuilder();
        int position = offset;
        int jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (position >= message.Length)
            {
                name = string.Empty;
                return false;
            }

            byte length = message[position];
            if (length == 0)
            {
                position++;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (!allowPointers || position + 1 >= message.Length || ++jumps > 16)
                {
                    name = string.Empty;
                    return false;
                }

                int target = ((length & 0x3F) << 8) | message[position + 1];
                if (!jumped)
                {
                    offset = position + 2;
                    jumped = true;
                }

                position = target;
                continue;
            }

            if ((length & 0xC0) != 0 || position + 1 + length > message.Length || builder.Length + length > 254)
            {
                name = string.Empty;
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(message.Slice(position + 1, length)));
            position += 1 + length;
        }

        if (!jumped)
        {
            offset = position;
        }

        name = builder.ToString();
        return true;
    }
}
