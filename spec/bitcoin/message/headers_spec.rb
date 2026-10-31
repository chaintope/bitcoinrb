require 'spec_helper'

describe Bitcoin::Message::Headers do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::Headers.parse_from_payload('0200000020d74691935ea3e3a1a1b72191d9540ab6de1ac0f1ccb928b9a40b6f1c0000000059b250a16ae1bdd0d066f0bbff76722550783076372d9687550c31f565f72836cf8a5059ffff001de5baa2020000000020f5e0e8a8e4374d258a3067bdaee39db29a1e9f5a29f9585136150a0d000000002c6e32d84acfe697a08d8c2071a0956927fad8ab028b8969a7c3c794dced35cec2905059ffff001db75e520000'.htb)
    }
    it 'should be parsed' do
      expect(subject.headers.length).to eq(2)
      expect(subject.headers[0].block_hash).to eq('f5e0e8a8e4374d258a3067bdaee39db29a1e9f5a29f9585136150a0d00000000')
      expect(subject.headers[1].block_hash).to eq('a11ad960c23169f8fe050840edb3526a27bc057b0c51d30f509cee5300000000')
    end
  end

  describe 'parse from payload with an unusual tx count or a bad count' do
    let(:header1) { '00000020d74691935ea3e3a1a1b72191d9540ab6de1ac0f1ccb928b9a40b6f1c0000000059b250a16ae1bdd0d066f0bbff76722550783076372d9687550c31f565f72836cf8a5059ffff001de5baa202'.htb }
    let(:header2) { '00000020f5e0e8a8e4374d258a3067bdaee39db29a1e9f5a29f9585136150a0d000000002c6e32d84acfe697a08d8c2071a0956927fad8ab028b8969a7c3c794dced35cec2905059ffff001db75e5200'.htb }

    it 'should read the tx count as a CompactSize' do
      # Bitcoin Core reads the count and ignores it. A three byte count after the first header used to
      # shift the second header by two bytes.
      headers = Bitcoin::Message::Headers.parse_from_payload("\x02".b + header1 + "\xfd\xfd\x00".b + header2 + "\x00".b)
      expect(headers.headers.length).to eq(2)
      expect(headers.headers[1].block_hash).to eq('a11ad960c23169f8fe050840edb3526a27bc057b0c51d30f509cee5300000000')
      expect(headers.headers[1].version).to eq(536870912)
      # And like every CompactSize it has to be canonical.
      expect { Bitcoin::Message::Headers.parse_from_payload("\x02".b + header1 + "\xfd\x00\x00".b + header2 + "\x00".b) }.
        to raise_error(ArgumentError, 'CompactSize is not canonical.')
    end

    it 'should reject more headers than Bitcoin Core allows in one message' do
      payload = Bitcoin.pack_var_int(2001) + (header1 + "\x00".b) * 2001
      expect { Bitcoin::Message::Headers.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, /header count 2001 exceeds 2000/)
      expect(Bitcoin::Message::Headers.parse_from_payload(Bitcoin.pack_var_int(2000) + (header1 + "\x00".b) * 2000).headers.size).to eq(2000)
    end

    it 'should reject a truncated payload' do
      expect { Bitcoin::Message::Headers.parse_from_payload(''.b) }.to raise_error(ArgumentError, 'CompactSize is truncated.')
      expect { Bitcoin::Message::Headers.parse_from_payload("\x01".b + header1[0, 79]) }.to raise_error(ArgumentError, 'Payload is truncated.')
      expect { Bitcoin::Message::Headers.parse_from_payload("\x01".b + header1) }.to raise_error(ArgumentError, 'CompactSize is truncated.')
      expect { Bitcoin::Message::Headers.parse_from_payload("\x02".b + header1 + "\x00".b) }.to raise_error(ArgumentError, 'Payload is truncated.')
    end
  end

  describe 'to_pkt' do
    subject {
      h = Bitcoin::BlockHeader.parse_from_payload('00000020d74691935ea3e3a1a1b72191d9540ab6de1ac0f1ccb928b9a40b6f1c0000000059b250a16ae1bdd0d066f0bbff76722550783076372d9687550c31f565f72836cf8a5059ffff001de5baa20200'.htb)
      Bitcoin::Message::Headers.new([h]).to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b110907686561646572730000000000520000004306380f0100000020d74691935ea3e3a1a1b72191d9540ab6de1ac0f1ccb928b9a40b6f1c0000000059b250a16ae1bdd0d066f0bbff76722550783076372d9687550c31f565f72836cf8a5059ffff001de5baa20200'.htb)
    end
  end

end
