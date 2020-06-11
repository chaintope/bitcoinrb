require 'spec_helper'

describe Bitcoin::Message::GetCFilters do

  describe '#parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::GetCFilters.parse_from_payload('00e80300004b75600dbb3ce35fa383b7439be10a66a2e7023bcb6b3a45bf83e57de020a954'.htb)
    }
    it 'should be parsed.' do
      expect(subject.filter_type).to eq(0)
      expect(subject.start_height).to eq(1_000)
      expect(subject.stop_hash).to eq('4b75600dbb3ce35fa383b7439be10a66a2e7023bcb6b3a45bf83e57de020a954')
      expect(subject.to_pkt.bth).to eq('fabfb5da6765746366696c7465727300250000000dc31ee100e80300004b75600dbb3ce35fa383b7439be10a66a2e7023bcb6b3a45bf83e57de020a954')
    end
  end

end