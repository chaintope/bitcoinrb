require 'spec_helper'

describe Bitcoin::Message::Pong do

  describe 'to_pkt' do
    subject { Bitcoin::Message::Pong.new(2989705664).to_pkt}
    it 'should be generate' do
      expect(subject.bth).to eq('0b110907706f6e670000000000000000080000006d539cecc04933b200000000')
    end
  end

  describe 'parse from payload' do
    subject { Bitcoin::Message::Pong.parse_from_payload('c04933b200000000'.htb)}
    it 'should be parsed' do
      expect(subject.nonce).to eq(2989705664)
    end
  end

end
