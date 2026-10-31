require 'spec_helper'

RSpec.describe ECDSA::Format::PointOctetString do

  describe '#decode' do
    it 'support allow_hybrid flag.' do
      hybrid_key = '0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.htb
      expect{ECDSA::Format::PointOctetString.decode(hybrid_key, ECDSA::Group::Secp256k1)}.to raise_error(ECDSA::Format::DecodeError)
      expect{ECDSA::Format::PointOctetString.decode(hybrid_key, ECDSA::Group::Secp256k1, allow_hybrid: true)}.not_to raise_error
    end

    it 'should reject a hybrid key whose parity byte does not match y' do
      # The generator point has an even y, so 0x06 is the right prefix and 0x07 the wrong one.
      point = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
      right = ECDSA::Format::PointOctetString.decode(('06' + point).htb, ECDSA::Group::Secp256k1, allow_hybrid: true)
      expect(right.y.even?).to be true
      expect{ECDSA::Format::PointOctetString.decode(('07' + point).htb, ECDSA::Group::Secp256k1, allow_hybrid: true)}.
        to raise_error(ECDSA::Format::DecodeError, /parity byte which does not match y/)
      expect(Bitcoin::Secp256k1::Ruby.parse_ec_pubkey?('06' + point, true)).to be true
      expect(Bitcoin::Secp256k1::Ruby.parse_ec_pubkey?('07' + point, true)).to be false
      expect{Bitcoin::Key.new(pubkey: '07' + point, key_type: Bitcoin::Key::TYPES[:uncompressed], allow_hybrid: true)}.
        to raise_error(ArgumentError, 'Invalid public key.')
    end
  end

end