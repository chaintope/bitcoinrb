require 'spec_helper'

describe Bitcoin::Message::Ping do

  describe 'to_pkt' do
    subject{ Bitcoin::Message::Ping.new(2989705664).to_pkt }
    it 'should be generate' do
      expect(subject.bth).to eq('0b11090770696e670000000000000000080000006d539cecc04933b200000000')
    end
  end

  describe 'parse from payload' do
    subject { Bitcoin::Message::Ping.parse_from_payload('c04933b200000000'.htb) }
    it 'should be parsed' do
      expect(subject.nonce).to eq(2989705664)
      expect(subject.to_response.nonce).to eq(2989705664)
    end
  end

  describe 'parse from payload without nonce' do
    subject { Bitcoin::Message::Ping.parse_from_payload('') }
    it 'should be parsed as ping without nonce' do
      expect(subject.nonce).to be_nil
      expect(subject.to_payload).to eq('')
      expect(subject.to_response).to be_nil
    end
  end

end