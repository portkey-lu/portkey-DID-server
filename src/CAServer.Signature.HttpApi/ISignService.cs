using System;
using AElf;
using AElf.Cryptography;
using AElf.KeyStore;
using Microsoft.Extensions.Options;

namespace CAServer.Signature;

public interface ISignService
{
    byte[] Sign(string msg);
}

public class KeyStoreSignService : ISignService, IDisposable
{
    private readonly KeyStoreOptions _keyStoreOptions;
    
    public KeyStoreSignService(IOptions<KeyStoreOptions> keyStoreOptions)
    {
        _keyStoreOptions = keyStoreOptions.Value;
    }

    public byte[] Sign(string msg)
    {
        var aelfKeyStoreService = new AElfKeyStoreService();
        return CryptoHelper.SignWithPrivateKey(
            aelfKeyStoreService.DecryptKeyStoreFromJson(_keyStoreOptions.Password, _keyStoreOptions.Path),
            ByteArrayHelper.HexStringToByteArray(msg));
    }

    public void Dispose()
    {
        // todo
    }
}