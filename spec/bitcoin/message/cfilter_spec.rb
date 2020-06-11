require 'spec_helper'

describe Bitcoin::Message::CFilter do

  describe '#parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::CFilter.parse_from_payload('00037f1dcd4c46e1305ceaef7083a56c3824db5439e5d09e349eed59500ee6c86704011c9340'.htb)
    }
    it 'should be parsed.' do
      expect(subject.filter_type).to eq(0)
      expect(subject.block_hash).to eq('037f1dcd4c46e1305ceaef7083a56c3824db5439e5d09e349eed59500ee6c867')
      expect(subject.block_hash.htb.bytesize).to eq(32)
      expect(subject.filter).to eq('011c9340')
      expect(subject.to_pkt.bth).to eq('fabfb5da6366696c746572000000000026000000ad8e627f00037f1dcd4c46e1305ceaef7083a56c3824db5439e5d09e349eed59500ee6c86704011c9340')
    end
  end

end