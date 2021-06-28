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
        # tree leaves tree.
        #       N0
        #    /     \
        #   N1      C
        #  /  \
        # A    B
        key1 = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        key2 = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
        key3 = '31fe7061656bea2a36aa60a2f7ef940578049273746935d296426dc0afd86b68'
        script1 = Bitcoin::Script.new << key1 << OP_CHECKSIG
        script2 = Bitcoin::Script.new << key2 << OP_CHECKSIG
        script3 = Bitcoin::Script.new << key3 << OP_CHECKSIG
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key,script1, script2, script3)
        expect(builder.build.to_addr).to eq('bc1pkysykpr4e9alyu7wthrtmp2km6sylrjlz83qzrsjkxhdaazyfrusyk2pwg')

        # four leaves tree.
        #       N0
        #    /     \
        #   N1      N2
        #  /  \    /  \
        # A    B  C    D
        key4 = 'a016430f275c30cb15f399aa807cc9bde6b2c4c80c84be3bb27912089c18e363'
        script4 = Bitcoin::Script.new << key4 << OP_CHECKSIG
        builder << script4
        expect(builder.build.to_addr).to eq('bc1pwr9amrwnxplrxdealu7h9rnfxusrdu8266ec83jpch3khjys9t9scpnpv6')

        # five leaves tree.
        #           N0
        #        /     \
        #       N1      E
        #    /     \
        #   N2      N3
        #  /  \    /  \
        # A    B  C    D
        key5 = 'b256afd27b26b0db101fd4a3d99afdd876dd2aaa5be967198882476bf425c301'
        script5 = Bitcoin::Script.new << key5 << OP_CHECKSIG
        builder << script5
        expect(builder.build.to_addr).to eq('bc1pmxmu5slfv0zm3dsju74djrhkhd75qwpwht688vn0kw5f9j4z855sdx8c39')

        # six leaves tree.
        #            N0
        #        /        \
        #       N1         N2
        #    /     \      /  \
        #   N3      N4   E    F
        #  /  \    /  \
        # A    B  C    D
        key6 = '0e5ba1cfed1fe76ff81558731b7279ed23ddd95ce0fd67adc94584e80abbe987'
        script6 = Bitcoin::Script.new << key6 << OP_CHECKSIG
        builder << script6
        expect(builder.build.to_addr).to eq('bc1peyxqpa4c4uzg9jzt7q92c94sk7kmj2uzhh2phuv8q8tkjrw6y67qf0u6mu')
      end
    end
  end

end