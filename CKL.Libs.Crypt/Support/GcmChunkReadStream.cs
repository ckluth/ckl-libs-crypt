using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// A read-only stream that reverses <see cref="GcmChunkWriteStream"/>: it reads fixed-size
/// <c>(ciphertext‖tag)</c> chunks from an underlying source, verifies each chunk's AES-256-GCM tag
/// (with the per-chunk nonce and associated data — chunk index, final marker, and header bytes),
/// and yields the authenticated plaintext (see ADR 0011). A one-chunk lookahead marks the final
/// chunk, so truncation and extension both surface as tag failures. A container with <b>no</b>
/// framed chunks is rejected — decryption always authenticates at least one chunk, so a
/// header-only blob can never decode to an "empty" success. Any tag mismatch throws a
/// <see cref="CryptographicException"/>, surfaced as a uniform decryption failure. Only ~one chunk
/// is buffered — the pipeline stays streaming.
/// </summary>
internal sealed class GcmChunkReadStream : Stream
{
    private readonly Stream _source;
    private readonly AesGcm _aes;
    private readonly byte[] _headerBytes;
    private readonly byte[] _nonceBase;
    private readonly int _chunkSize;
    private readonly int _cipherChunkSize;
    private readonly bool _leaveOpen;

    private byte[]? _current;
    private byte[] _plain = [];
    private int _plainOffset;
    private long _index;
    private bool _started;
    private bool _finished;

    internal GcmChunkReadStream(Stream source, byte[] key, byte[] headerBytes, byte[] nonceBase, int chunkSize, bool leaveOpen = false)
    {
        _source = source;
        _aes = new AesGcm(key, CryptoHeader.TagLength);
        _headerBytes = headerBytes;
        _nonceBase = nonceBase;
        _chunkSize = chunkSize;
        _cipherChunkSize = chunkSize + CryptoHeader.TagLength;
        _leaveOpen = leaveOpen;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (count > 0)
        {
            EnsurePlain();
            var available = _plain.Length - _plainOffset;
            if (available == 0)
                break;

            var take = Math.Min(available, count);
            Buffer.BlockCopy(_plain, _plainOffset, buffer, offset, take);
            _plainOffset += take;
            offset += take;
            count -= take;
            total += take;
        }

        return total;
    }

    private void EnsurePlain()
    {
        if (_plainOffset < _plain.Length || _finished)
            return;

        if (!_started)
        {
            _current = ReadCipherChunk();
            if (_current is null)
                throw new InvalidDataException("Container has no framed chunks.");
            _started = true;
        }

        var next = ReadCipherChunk();
        var isFinal = next is null;

        _plain = DecryptChunk(_current!, isFinal);
        _plainOffset = 0;
        _index++;

        if (isFinal)
            _finished = true;
        else
            _current = next;
    }

    private byte[] DecryptChunk(byte[] cipherChunk, bool isFinal)
    {
        if (cipherChunk.Length < CryptoHeader.TagLength)
            throw new InvalidDataException("Truncated framed chunk.");
        if (!isFinal && cipherChunk.Length != _cipherChunkSize)
            throw new InvalidDataException("Malformed non-final chunk.");

        var cipherLength = cipherChunk.Length - CryptoHeader.TagLength;
        var nonce = AesCryptoCore.DeriveNonce(_nonceBase, _index);
        var aad = AesCryptoCore.BuildAad(_headerBytes, _index, isFinal);
        var plaintext = new byte[cipherLength];

        _aes.Decrypt(
            nonce,
            cipherChunk.AsSpan(0, cipherLength),
            cipherChunk.AsSpan(cipherLength, CryptoHeader.TagLength),
            plaintext,
            aad);

        return plaintext;
    }

    private byte[]? ReadCipherChunk()
    {
        var buffer = new byte[_cipherChunkSize];
        var read = 0;
        while (read < _cipherChunkSize)
        {
            var n = _source.Read(buffer, read, _cipherChunkSize - read);
            if (n == 0)
                break;
            read += n;
        }

        if (read == 0)
            return null;
        if (read == _cipherChunkSize)
            return buffer;

        var trimmed = new byte[read];
        Buffer.BlockCopy(buffer, 0, trimmed, 0, read);
        return trimmed;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _aes.Dispose();
            if (!_leaveOpen)
                _source.Dispose();
        }

        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
