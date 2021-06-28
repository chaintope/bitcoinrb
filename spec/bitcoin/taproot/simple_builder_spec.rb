require 'spec_helper'

include Bitcoin::Opcodes

RSpec.describe Bitcoin::Taproot::SimpleBuilder, network: :mainnet do

  describe '#initialize' do
    it 'should generate object' do
      key = Bitcoin::Key.new(priv_key: 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866')
      expect{Bitcoin::Taproot::SimpleBuilder.new('')}.to raise_error(Bitcoin::Taproot::Error, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.pubkey)}.to raise_error(Bitcoin::Taproot::Error, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey)}.not_to raise_error
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey, [key.xonly_pubkey])}.to raise_error(Bitcoin::Taproot::Error, 'script must be Bitcoin::Script object')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey, Bitcoin::Script.to_p2pkh(key.hash160))}.not_to raise_error
    end
  end

  describe 'add condition' do
    it 'should add condition' do
      key = Bitcoin::Key.new(priv_key: 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866')
      builder = Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey)
      expect(builder.leaves.size).to eq(0)
      builder << Bitcoin::Script.to_p2pkh(key.hash160)
      expect(builder.leaves.size).to eq(1)
      expect{builder << key}.to raise_error(Bitcoin::Taproot::Error, 'script must be Bitcoin::Script object')
    end
  end

  describe '#build' do
    let(:internal_key) { '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }
    context 'has no script' do
      it 'should generate P2TR script' do
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key)
        expect(builder.build.to_addr).to eq('bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9')
      end
    end

    context 'hash scripts' do
      it 'should generate P2TR script' do
        key1 = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        key2 = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
        key3 = '31fe7061656bea2a36aa60a2f7ef940578049273746935d296426dc0afd86b68'
        script1 = Bitcoin::Script.new << key1 << OP_CHECKSIG
        script2 = Bitcoin::Script.new << key2 << OP_CHECKSIG
        script3 = Bitcoin::Script.new << key3 << OP_CHECKSIG
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key,script1, script2, script3)
        p2tr = builder.build
        expect(p2tr.to_addr).to eq('bc1pkysykpr4e9alyu7wthrtmp2km6sylrjlz83qzrsjkxhdaazyfrusyk2pwg')
      end
    end
  end

end