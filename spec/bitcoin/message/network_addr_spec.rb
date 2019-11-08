require 'spec_helper'

describe Bitcoin::Message::NetworkAddr do

  describe '#parse_from_payload' do
    subject {
      Bitcoin::Message::NetworkAddr.parse_from_payload('010000000000000000000000000000000000ffffc61b6409208d'.htb)
    }
    it 'should be parsed' do
      expect(subject.ip).to eq('198.27.100.9')
      expect(subject.port).to eq(8333)
      expect(subject.services).to eq(1)
      expect(subject.to_payload(true).bth).to eq('010000000000000000000000000000000000ffffc61b6409208d')
    end
  end

  describe '#to_payload' do
    subject {
      p = Bitcoin::Message::NetworkAddr.new(port: 18333).to_payload(true)
      Bitcoin::Message::NetworkAddr.parse_from_payload(p)
    }
    it 'should be generate payload' do
      expect(subject.port).to eq(18333)
      expect(subject.ip).to eq('127.0.0.1')
      expect(subject.services).to eq(Bitcoin::Message::DEFAULT_SERVICE_FLAGS)
    end
  end

end