using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// A write-only stream that frames everything written to it into fixed-size AES-256-GCM chunks and
/// writes each <c>(ciphertext‖tag)</c> block to an underlying destination (see ADR 0011). Plaintext
/// is buffered up to one chunk; a full chunk is only emitted as a <b>non-final</b> chunk once more
/// data arrives, so every non-final chunk is exactly <see cref="_chunkSize"/> bytes. The last chunk
/// (possibly short, possibly empty) is emitted on <see cref="Dispose(bool)"/>, so exactly one final
/// chunk is always written — even for empty input. Per-chunk nonce and associated data come from
/// <see cref="AesCryptoCore.DeriveNonce"/>/<see cref="AesCryptoCore.BuildAad"/>, binding the chunk
/// index, a final-chunk marker, and the exact header bytes so reorder, truncation, duplication, and
/// header-field tampering all fail the tag. Only ~one chunk is buffered — the pipeline stays
/// streaming.
/// </summary>
internal sealed class GcmChunkWriteStream : Stream
{
    private readonly Stream _destination;
    private readonly AesGcm _aes;
    private readonly byte[] _headerBytes;
    private readonly byte[] _nonceBase;
    private readonly int _chunkSize;
    private readonly bool _leaveOpen;
    private readonly byte[] _pending;
    private int _pendingCount;
    private long _index;
    private bool _finalWritten;

    internal GcmChunkWriteStream(Stream destination, byte[] key, byte[] headerBytes, byte[] nonceBase, int chunkSize, bool leaveOpen = false)
    {
        _destination = destination;
        _aes = new AesGcm(key, CryptoHeader.TagLength);
        _headerBytes = headerBytes;
        _nonceBase = nonceBase;
        _chunkSize = chunkSize;
        _leaveOpen = leaveOpen;
        _pending = new byte[chunkSize];
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            if (_pendingCount == _chunkSize)
            {
                EmitChunk(_pendingCount, isFinal: false);
                _pendingCount = 0;
            }

            var take = Math.Min(count, _chunkSize - _pendingCount);
            Buffer.BlockCopy(buffer, offset, _pending, _pendingCount, take);
            _pendingCount += take;
            offset += take;
            count -= take;
        }
    }

    public override void Flush() => _destination.Flush();

    private void EmitChunk(int length, bool isFinal)
    {
        var nonce = AesCryptoCore.DeriveNonce(_nonceBase, _index);
        var aad = AesCryptoCore.BuildAad(_headerBytes, _index, isFinal);
        var ciphertext = new byte[length];
        var tag = new byte[CryptoHeader.TagLength];

        _aes.Encrypt(nonce, _pending.AsSpan(0, length), ciphertext, tag, aad);

        _destination.Write(ciphertext, 0, ciphertext.Length);
        _destination.Write(tag, 0, tag.Length);
        _index++;
    }

    private void WriteFinalChunk()
    {
        if (_finalWritten)
            return;

        EmitChunk(_pendingCount, isFinal: true);
        _pendingCount = 0;
        _finalWritten = true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            WriteFinalChunk();
            _aes.Dispose();
            if (!_leaveOpen)
                _destination.Dispose();
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
