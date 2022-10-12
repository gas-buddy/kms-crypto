// This test validates that the object hash dependency hasn't changed. (Or at least as best we can)
import ohash from 'object-hash';

test('Object hash consistency', () => {
  const hash = Buffer.from(ohash(
    {
      context: { service: 'foobar' },
      plain: 'This is a test string',
    },
    {
      algorithm: 'sha256',
      encoding: 'buffer',
    },
  ));
  expect(hash.toString('hex')).toEqual('6b991b9f2fa2aa57ac433fa51c6d7d6a413e132bfd44b11efcd30b4828adad76');

  const hash2 = ohash({ service: 'foobar' });
  expect(hash2).toEqual('8d796d521be01b2b1d60aef0f07ef252bece62ec');
});
