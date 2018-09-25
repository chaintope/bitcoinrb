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
