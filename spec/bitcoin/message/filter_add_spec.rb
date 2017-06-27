require 'spec_helper'

describe Bitcoin::Message::FilterAdd do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::FilterAdd.parse_from_payload('20fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b'.htb)
    }
    it 'should be parsed' do
      expect(subject.element).to eq('0bcb16af267dee77ed8761662d31ee9d9a1bf1e4d268a9e7127407ebb3f9acfd')
    end
  end

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::FilterAdd.new('0bcb16af267dee77ed8761662d31ee9d9a1bf1e4d268a9e7127407ebb3f9acfd').to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b11090766696c7465726164640000002100000072851a0a20fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b'.htb)
    end
  end

end