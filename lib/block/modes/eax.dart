import 'dart:math' show min;
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/modes/sic.dart';
import 'package:pointycastle/macs/cmac.dart';
import 'package:pointycastle/src/registry/registry.dart';

class EAXBlockCipher implements AEADBlockCipher {
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      '/EAX',
      (_, final Match match) => () {
            var underlying = BlockCipher(match.group(1));
            return EAXBlockCipher(underlying);
          });

  SICBlockCipher _cipher;

  EAXBlockCipher(BlockCipher underlyingCipher) {
    _mac = CMac(underlyingCipher, underlyingCipher.blockSize * 8);
    _cipher = SICBlockCipher(underlyingCipher.blockSize, underlyingCipher);
  }

  static const nTAG = 0x0;
  static const hTAG = 0x1;
  static const cTAG = 0x2;

  // These fields are set by init and not modified by processing
  bool _forEncryption;
  int _macSize;
  Uint8List _lastKey;
  Uint8List _nonce;
  Uint8List _initialAssociatedText;

  // These fields are modified during processing
  Uint8List _bufBlock;
  int _bufOff;
  Uint8List _lastMacSizeBytes;
  int _lastMacSizeBytesOff;

  Uint8List _macBlock;
  Mac _mac;

  @override
  String get algorithmName => '${underlyingCipher.algorithmName}/EAX';

  @override
  int get blockSize => underlyingCipher.blockSize;

  /// The underlying cipher
  BlockCipher get underlyingCipher => _cipher;

  /// True if initialized for encryption
  bool get forEncryption => _forEncryption;

  /// The nonce or iv as set by the initialization
  Uint8List get nonce => _nonce;

  /// The additional authenticated data as set by the initialization
  Uint8List get aad => _initialAssociatedText;

  /// Any remaining input yet to be processed
  Uint8List get remainingInput => Uint8List.view(_bufBlock.buffer, _bufBlock.offsetInBytes, _bufOff);

  /// The length in bytes of the authentication tag
  int get macSize => _macSize;

  /// The value of the authentication tag associated with the last processed
  /// data
  Uint8List get mac {
    // TODO
    var mac = Uint8List.fromList(_macBlock);
    return mac;
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    // TODO
    // Not called
    print('processBlock');
    return null;
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    // TODO
    int extra = _bufOff;
    var tmp = Uint8List(_bufBlock.length);
    _bufOff = 0;

    if (forEncryption) {
      if (out.length < (outOff + extra + macSize)) {
        throw InvalidCipherTextException('Output buffer too short');
      }
      _cipher.processBlock(_bufBlock, 0, tmp, 0);
      // tmp should be on this point:
      // [29, -85, 11, -47, -117, -70, -88, 67, 1, -125, 6, -42, 29, -94, -12, 4]
      // but it show:
      // [44, 230, 146, 127, 21, 198, 5, 99, 219, 192, 197, 254, 38, 237, 168, 35]

      out.setAll(outOff, tmp);
      _mac.update(tmp, 0, extra);
    } else {
      // TODO
    }

    return null;
  }

  /// When decrypting, validates the generated authentication tag with the one
  /// in the input stream. When not equal throws [InvalidCipherTextException].
  /// This method should be called from the [doFinal] method.
  void validateMac() {
    if (forEncryption) {
      return;
    }
    if (_lastMacSizeBytesOff != macSize) {
      throw InvalidCipherTextException('Input data too short');
    }
    if (!_compareLists(mac, _lastMacSizeBytes)) {
      throw InvalidCipherTextException('Authentication tag check failed');
    }
  }

  bool _compareLists(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  void init(bool forEncryption, CipherParameters params) {
    _forEncryption = forEncryption;

    KeyParameter keyParam;
    Uint8List newNonce;

    if (params is AEADParameters) {
      var param = params;

      newNonce = param.nonce;
      _initialAssociatedText = param.associatedData ?? Uint8List(0);

      var macSizeBits = param.macSize;
      if (macSizeBits < 32 || macSizeBits > 256 || macSizeBits % 8 != 0) {
        throw ArgumentError('Invalid value for MAC size: $macSizeBits');
      }

      _macSize = macSizeBits ~/ 8;
      keyParam = param.parameters as KeyParameter;
    } else if (params is ParametersWithIV) {
      var param = params;

      newNonce = param.iv;
      _initialAssociatedText = Uint8List(0);
      _macSize = 16;
      keyParam = param.parameters as KeyParameter;
    } else {
      throw ArgumentError('invalid parameters passed to EAX');
    }

    // Key reuse implemented in CBC mode of underlying CMac
    _mac.init(keyParam);

    var bufLength = forEncryption ? blockSize : (blockSize + _macSize);
    _bufBlock = Uint8List(bufLength);

    if (newNonce == null || newNonce.isEmpty) {
      throw ArgumentError('IV must be at least 1 byte');
    }

    _nonce = newNonce;
    _lastKey = keyParam.key;
    _lastMacSizeBytes = Uint8List(macSize);

    reset();
  }

  @override
  Uint8List process(Uint8List data) {
    var out = Uint8List(_getOutputSize(data.length));

    var len = processBytes(data, 0, data.length, out, 0);

    len += doFinal(out, len);

    return Uint8List.view(out.buffer, 0, len);
  }

  @override
  int processBytes(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    if (len == 0) return 0;

    if (forEncryption) {
      // all bytes are plain text bytes
      return _processCipherBytes(inp, inpOff, len, out, outOff);
    }

    // last macSize bytes are possibly mac bytes and not cipher text bytes
    // -> keep them in buffer
    var cipherLen = _lastMacSizeBytesOff + len - macSize;

    var resultLen = 0;

    if (cipherLen > 0 && _lastMacSizeBytesOff > 0) {
      // at least part of the buffer are actually cipher text bytes
      // process them and update the buffer

      var l = min(_lastMacSizeBytesOff, cipherLen);
      resultLen += _processCipherBytes(_lastMacSizeBytes, 0, min(_lastMacSizeBytesOff, cipherLen), out, outOff);
      outOff += resultLen;
      cipherLen -= l;
      _lastMacSizeBytes.setRange(0, macSize - l, _lastMacSizeBytes.skip(l));
      _lastMacSizeBytesOff -= l;
    }

    if (cipherLen > 0) {
      // part of the input are cipher text bytes
      resultLen += _processCipherBytes(inp, inpOff, cipherLen, out, outOff);
    }

    _lastMacSizeBytes.setRange(_lastMacSizeBytesOff, _lastMacSizeBytesOff + len - cipherLen, inp.skip(inpOff + cipherLen));
    _lastMacSizeBytesOff += len - cipherLen;

    return resultLen;
  }

  int _processCipherBytes(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    if (len == 0) return 0;

    var resultLen = 0;

    if (_bufOff != 0) {
      // add to buffer until full
      var end = blockSize < _bufOff + len ? blockSize : _bufOff + len;
      _bufBlock.setRange(_bufOff, end, inp.skip(inpOff));
      len -= end - _bufOff;
      _bufOff = end;

      // if buffer full and has more data -> process buffer
      if (_bufOff == blockSize && len > 0) {
        processBlock(_bufBlock, 0, out, outOff);
        _bufOff = 0;
        resultLen += blockSize;
      }
    }

    // process all full blocks
    while (len > blockSize) {
      processBlock(inp, inpOff, out, outOff + resultLen);
      inpOff += blockSize;
      len -= blockSize;
      resultLen += blockSize;
    }

    // keep last block in buffer
    if (len > 0) {
      _bufBlock.setRange(0, len, inp.skip(inpOff));
      _bufOff = len;
    }

    return resultLen;
  }

  @override
  void reset() {
    _bufOff = 0;
    _lastMacSizeBytesOff = 0;

    if (_lastKey == null) return;

    prepare(KeyParameter(_lastKey));
    processAADBytes(_initialAssociatedText, 0, _initialAssociatedText.length);
  }

  /// Prepare for a new stream of data. This method is called during
  /// initialization and reset.
  void prepare(KeyParameter keyParam) {
    // TODO
    var tag = Uint8List(blockSize);
    tag[blockSize - 1] = hTAG;
    _mac.update(tag, 0, blockSize);
  }

  /// Processes the additional authentication data
  void processAADBytes(Uint8List inp, int inpOff, int len) {
    // TODO
    _mac.update(inp, inpOff, len);
  }

  int _getOutputSize(int length) => (length + (forEncryption ? macSize : -macSize) + blockSize - 1) ~/ blockSize * blockSize;
}
