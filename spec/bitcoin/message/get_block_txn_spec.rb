require 'spec_helper'

describe Bitcoin::Message::GetBlockTxn do

  describe '#parse_from_payload' do
    subject{
      Bitcoin::Message::GetBlockTxn.parse_from_payload('ca8fb932735c229005040eeefed540f36dfab54c68acd92e54ad69c200000000050500000000'.htb)
    }
    it 'should be parsed.' do
      expect(subject.request.block_hash.htb.reverse.bth).to eq('00000000c269ad542ed9ac684cb5fa6df340d5feee0e040590225c7332b98fca')
      expect(subject.request.indexes).to eq([5, 6, 7, 8, 9])
      expect(subject.to_hex).to eq('ca8fb932735c229005040eeefed540f36dfab54c68acd92e54ad69c200000000050500000000')
    end
  end

end
