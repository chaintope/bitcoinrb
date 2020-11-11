require 'spec_helper'

describe Bitcoin::Secp256k1::Ruby do

  describe '#generate_key_pair' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(33)
        expect(['02', '03'].include?(subject[1].htb[0].bth)).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(65)
        expect(subject[1].htb[0].bth).to eq('04')
      end
    end
  end

  describe '#generate_key' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key }
      it 'should be generate' do
        expect(subject.compressed?).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key(compressed: false) }
      it 'should be generate' do
        expect(subject.compressed?).to be false
      end
    end
  end

  describe '#generate_pubkey' do
    subject { Bitcoin::Secp256k1::Ruby.generate_pubkey(privkey, compressed: true) }

    let(:privkey) { '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff' }

    it { is_expected.to eq '020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a' }
  end

  describe '#sign_data/#verify_data', use_secp256k1: true do

    context 'ecdsa' do
      it 'should be signed' do
        message = 'message'.htb
        priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
        pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
        sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key)
        expect(Bitcoin::Secp256k1::Ruby.verify_sig(message, sig, pub_key)).to be true

        # generate signature compatible with RFC 6979
        priv_key = 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'
        message = '63cec688ee06a91e913875356dd4dea2f8e0f2a2659885372da2a37e32c7532e'.htb
        signature = '30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed'
        expect(Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key).bth).to eq(signature)

        priv_key = Bitcoin::Key.generate.priv_key
        secp256k1_sig = Bitcoin::Secp256k1::Native.sign_data(message, priv_key)
        ruby_sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key)
        expect(ruby_sig.bth).to eq(secp256k1_sig.bth)
      end
    end

    context 'schnorr' do
      it 'should be signed' do
        key = Bitcoin::Key.generate
        message = '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'.htb
        priv_key = key.priv_key
        aux_rand = 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906'.htb
        pub_key = key.pubkey
        sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key, aux_rand, algo: :schnorr)
        sig2 = Bitcoin::Secp256k1::Native.sign_data(message, priv_key, aux_rand, algo: :schnorr)
        expect(sig.bth).to eq(sig2.bth)
        expect(Bitcoin::Secp256k1::Ruby.verify_sig(message, sig, pub_key[2..-1], algo: :schnorr)).to be true
      end
    end
  end

  describe '#valid_xonly_pubkey' do
    context 'valid public key' do
      it 'should return true.' do
        expect(Bitcoin::Secp256k1::Ruby.valid_xonly_pubkey?('92ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')).to be true
      end
    end

    context 'invalid public key(not on curve)' do
      it 'should return false.' do
        expect(Bitcoin::Secp256k1::Ruby.valid_xonly_pubkey?('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')).to be false
        expect(Bitcoin::Secp256k1::Ruby.valid_xonly_pubkey?('00' * 32)).to be false
      end
    end
  end

end