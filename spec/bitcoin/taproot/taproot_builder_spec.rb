require 'spec_helper'

RSpec.describe Bitcoin::Taproot::Builder do

  describe '#initialize' do
    it 'should generate object' do
      key = Bitcoin::Key.new(priv_key: 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866')
      expect{Bitcoin::Taproot::Builder.new('')}.to raise_error(Bitcoin::Taproot::BuildError, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::Builder.new(key.pubkey)}.to raise_error(Bitcoin::Taproot::BuildError, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::Builder.new(key.xonly_pubkey)}.not_to raise_error
      expect{Bitcoin::Taproot::Builder.new(key.xonly_pubkey, [key.xonly_pubkey])}.to raise_error(Bitcoin::Taproot::BuildError, 'script must be Bitcoin::Script object')
      expect{Bitcoin::Taproot::Builder.new(key.xonly_pubkey, Bitcoin::Script.to_p2pkh(key.hash160))}.not_to raise_error
    end
  end

end