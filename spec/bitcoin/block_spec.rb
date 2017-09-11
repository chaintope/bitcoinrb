require 'spec_helper'

describe Bitcoin::Block do

  subject {
    payload = load_block('0000000000343e7e31a6233667fd6ed5288d60ed7e894ae5d53beb0dffc89170').htb
    Bitcoin::Message::Block.parse_from_payload(payload).to_block
  }

  describe 'calculate size' do
    it 'should be calculate.' do
      expect(subject.stripped_size).to eq(34647)
      expect(subject.size).to eq(34792)
      expect(subject.weight).to eq(138733)
    end
  end

end