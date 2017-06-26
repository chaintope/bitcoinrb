require 'spec_helper'

describe Bitcoin::Message::FilterClear do

  describe 'to_pkt' do
    subject { Bitcoin::Message::FilterClear.new.to_pkt }
    it 'should be generate' do
      expect(subject).to eq('0b11090766696c746572636c65617200000000005df6e0e2'.htb)
    end
  end

end