require 'spec_helper'

describe Bitcoin::Message::GetCFCheckpt do

  describe '#parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::GetCFCheckpt.parse_from_payload('0024b7278b7099b25da182ad89cdc6505ec1ee5a1a7124535963b86a8e37064648'.htb)
    }
    it 'should be parsed.' do
      expect(subject.filter_type).to eq(0)
      expect(subject.stop_hash).to eq('24b7278b7099b25da182ad89cdc6505ec1ee5a1a7124535963b86a8e37064648')
      expect(subject.stop_hash.htb.bytesize).to eq(32)
      expect(subject.to_pkt.bth).to eq('fabfb5da6765746366636865636b707421000000c4a7f2600024b7278b7099b25da182ad89cdc6505ec1ee5a1a7124535963b86a8e37064648')
    end
  end

end