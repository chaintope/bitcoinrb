require 'spec_helper'

RSpec.describe Bitcoin::Descriptor::MuSig, network: :mainnet do

  include Bitcoin::Descriptor

  describe 'Test Vector' do
    it do
      expect(rawtr(musig(
                     'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S',
                     '03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
                     '023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66'
                   )).to_hex).to eq('5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575')
      desc = 'rawtr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575')
      expect(tr(musig(
                  '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
                  '03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
                  '023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66'
                )).to_hex).to eq('512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312')
      desc = 'tr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312')
      expect(rawtr(musig(
                     'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                     'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                     path: '/0/0'
                   )).to_hex).to eq('51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc')
      desc = 'rawtr(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/0)'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc')
      expect(tr(musig(
                  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                  'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                  path: '/0/0'
                ),
                pk('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')
                ).to_hex).to eq('51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782')
      desc = 'tr(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/0,pk(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782')
      expect(tr('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
                pk(musig(
                     'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                     'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                     path: '/0/0'))
             ).to_hex).to eq('512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8')
      desc = 'tr(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,pk(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/0))'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8')
      expect(tr(musig(
                  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1',
                  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1',
                  path: '/2'
                )).to_hex).to eq('5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c')
      desc = 'tr(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1)/2)'
      expect(Bitcoin::Descriptor.parse(desc).to_hex)
        .to eq('5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c')

      # invalid case
      keys = %w[02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9 03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659 023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66]
      expect{pk(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in top-level pk().')
      expect{pkh(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in top-level pkh().')
      expect{wpkh(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in wpkh().')
      expect{combo(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in top-level combo().')
      expect{wsh(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in wsh().')
      expect{sh(musig(*keys)).to_hex}.to raise_error(ArgumentError, 'musig() is not allowed in sh().')
      expect{tr(musig(*keys, path: '/0/0'))}.to raise_error(ArgumentError, 'Ranged musig() requires all participants to be xpubs.')
      expect{tr(musig(
                  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>',
                  'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                  path: '/<2;3>'))}.to raise_error(ArgumentError, 'Key multipath are not supported.')
      expect{tr(musig(
                  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                  'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                  path: '/0h/0'))}.to raise_error(ArgumentError, 'musig() cannot have hardened child derivation.')
    end
  end
end