require 'spec_helper'

describe Bitcoin::Message::FilterLoad do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::FilterLoad.parse_from_payload('02b50f0b0000000000000000'.htb)
    }
    it 'should be parsed' do
      expect(subject.filter.size).to eq(2)
      expect(subject.filter).to eq('b50f'.htb.unpack('CC'))
      expect(subject.func_count).to eq(11)
      expect(subject.tweak).to eq(0)
      expect(subject.flag).to eq(0)
    end
  end

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::FilterLoad.new([181, 15], 11, 0, 0).to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b11090766696c7465726c6f616400000c0000008b7f507b02b50f0b0000000000000000'.htb)
    end
  end

end