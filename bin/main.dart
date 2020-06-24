import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/eax.dart';

void main(List<String> arguments) {
  final data = Uint8List.fromList([1, 2, 3, 4]);
  final keyBytes = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
  final nonce = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
  final header = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);

  //var cipher = GCMBlockCipher(AESFastEngine());
  var cipher = EAXBlockCipher(AESFastEngine());
  final key = KeyParameter(keyBytes);
  cipher.init(true, AEADParameters(key, 128, nonce, header));

  var result = Uint8List(20);
  int olen = cipher.processBytes(data, 0, data.length, result, 0);
  cipher.doFinal(result, olen);

  print('actual: ${Int8List.fromList(result)}');

  var expected = [29, -85, 11, -47, 32, 109, 73, 120, -57, 62, 90, -20, 35, 25, -26, -35, -81, 99, 41, -62];
  print('expected: $expected');
}
