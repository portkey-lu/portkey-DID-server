using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AElf;
using AElf.Cryptography;
using AElf.KeyStore;
using CAServer.Signature.Dtos;
using Google.Protobuf;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Volo.Abp;

namespace CAServer.Signature;

[RemoteService]
[Route("api/app/signature")]
public class SignatureController : CAServerSignatureController
{
    private readonly ILogger<SignatureController> _logger;
    private readonly KeyStoreOptions _keyStoreOptions;
    private readonly AElfKeyStoreService _aelfKeyStoreService;


    public SignatureController(ILogger<SignatureController> logger,
        IOptions<KeyStoreOptions> keyStoreOptions,
        AElfKeyStoreService aelfKeyStoreService)
    {
        _logger = logger;
        _keyStoreOptions = keyStoreOptions.Value;
        _aelfKeyStoreService = aelfKeyStoreService;
    }

    [HttpPost]
    public async Task<SignResponseDto> SendSignAsync(
        SendSignatureDto input)
    {
        try
        {
            _logger.LogDebug("input PublicKey: {PublicKey}, HexMsg: {HexMsg}", input.PublicKey, input.HexMsg);
            var privateKey = _aelfKeyStoreService.DecryptKeyStoreFromFile(_keyStoreOptions.Password, 
                _keyStoreOptions.Path);
            var recoverableInfo = CryptoHelper.SignWithPrivateKey(privateKey,
                ByteArrayHelper.HexStringToByteArray(input.HexMsg));
            _logger.LogDebug("Signature result :{signatureResult}", recoverableInfo.ToHex());

            return new SignResponseDto
            {
                Signature = ByteString.CopyFrom(recoverableInfo).ToHex(),
            };
        }
        catch (Exception e)
        {
            _logger.LogError("Signature failed, error msg is {errorMsg}", e);
            throw new UserFriendlyException(e.Message);
        }
    }

}