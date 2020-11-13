require 'spec_helper'

RSpec.describe ECDSA::Format::PointOctetString do

  describe '#decode' do
    it 'support allow_hybrid flag.' do
      hybrid_key = '0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.htb
      expect{ECDSA::Format::PointOctetString.decode(hybrid_key, ECDSA::Group::Secp256k1)}.to raise_error(ECDSA::Format::DecodeError)
      expect{ECDSA::Format::PointOctetString.decode(hybrid_key, ECDSA::Group::Secp256k1, true)}.not_to raise_error(ECDSA::Format::DecodeError)
    end
  end

end