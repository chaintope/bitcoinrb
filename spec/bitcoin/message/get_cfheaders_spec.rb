require 'spec_helper'

describe Bitcoin::Message::GetCFHeaders do

  describe '#parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::GetCFHeaders.parse_from_payload('0001000000eb07535100f930e08933a82705333cfbb0d4e0387b8bba78e0d4c5d1b0f3cb14'.htb)
    }
    it 'should be parsed.' do
      expect(subject.filter_type).to eq(0)
      expect(subject.start_height).to eq(1)
      expect(subject.stop_hash).to eq('eb07535100f930e08933a82705333cfbb0d4e0387b8bba78e0d4c5d1b0f3cb14')
      expect(subject.to_pkt.bth).to eq('fabfb5da67657463666865616465727325000000bb8434a50001000000eb07535100f930e08933a82705333cfbb0d4e0387b8bba78e0d4c5d1b0f3cb14')
    end
  end

end