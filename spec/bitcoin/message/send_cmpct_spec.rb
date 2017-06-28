require 'spec_helper'

describe Bitcoin::Message::SendCmpct do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::SendCmpct.parse_from_payload('000100000000000000'.htb)
    }
    it 'should be parsed' do
      expect(subject.high?).to be false
      expect(subject.low?).to be true
      expect(subject.version).to eq(1)
    end
  end

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::SendCmpct.new(Bitcoin::Message::SendCmpct::MODE_LOW, 1).to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b11090773656e64636d70637400000009000000ccfe104a000100000000000000'.htb)
    end
  end

end
