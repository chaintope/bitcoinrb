require 'spec_helper'

describe Bitcoin::Base58 do

  describe 'encode/decode' do
    f = fixture_file('base58_encode_decode.json')
    f.each do |hex, encoded|
      it "should be encoded/decoded #{hex}, #{encoded}" do
        expect(Bitcoin::Base58.encode(hex)).to eq(encoded)
        expect(Bitcoin::Base58.decode(encoded)).to eq(hex)
      end
    end
  end

  describe 'valid base58 keys' do
    valid_json = fixture_file('key_io_valid.json')
    valid_json.each do |base58_str, payload, metadata|
      it "should be valid #{base58_str}, #{payload}, #{metadata}" do
        Bitcoin.chain_params = case metadata['chain']
                               when 'main' then :mainnet
                               when 'test' then :testnet
                               when 'signet' then :signet
                               else :regtest
                               end
        compressed = metadata['isCompressed'] ? metadata['isCompressed'] : false
        is_privkey = metadata['isPrivkey']
        if is_privkey
          key = Bitcoin::Key.from_wif(base58_str)
          expect(key.priv_key).to eq(payload)
          expect(key.compressed?).to eq(compressed)
        else
          script = Bitcoin::Script.parse_from_payload(payload.htb)
          expect(script.to_addr).to eq(base58_str)
        end
      end
    end
  end

  describe 'invalid base58 keys' do
    invalid_json = fixture_file('key_io_invalid.json')
    invalid_json.each do |json|
      it "should be invalid. #{json}" do
        base58_str = json[0]
        expect{Bitcoin::Key.from_wif(base58_str)}.to raise_error(ArgumentError)
      end
    end
  end

end
