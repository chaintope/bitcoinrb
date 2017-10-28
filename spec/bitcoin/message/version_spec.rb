# encoding: ascii-8bit
require 'spec_helper'

describe Bitcoin::Message::Version do

  describe 'to_payload and parse_from_payload' do
    subject {
      version = Bitcoin::Message::Version.new
      version.start_height = 50_000
      @nonce = version.nonce
      version.remote_addr = '83.243.59.57:8333'
      version.relay = false
      Bitcoin::Message::Version.parse_from_payload(version.to_payload)
    }
    it 'should parse payload' do
      expect(subject.services).to eq(Bitcoin::Message::DEFAULT_SERVICE_FLAGS)
      expect(subject.user_agent).to eq(Bitcoin::Message::USER_AGENT)
      expect(subject.local_addr).to eq('83.243.59.57:8333')
      expect(subject.relay).to be false
      expect(subject.nonce).to eq(@nonce)
      expect(subject.start_height).to eq(50_000)
    end
  end

  describe 'specify opts' do
    subject {
      Bitcoin::Message::Version.new(start_height: 500, remote_addr: '83.243.59.57:8333')
    }
    it 'should be applied.' do
      expect(subject.start_height).to eq(500)
      expect(subject.remote_addr).to eq('83.243.59.57:8333')
    end
  end

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::Version.new(local_addr: '127.0.0.1:18333',
                                    remote_addr: '127.0.0.1:18333',
                                    timestamp: 1497706959, services: 0,
                                    version: 70015,
                                    user_agent: '/bitcoinrb:0.1.0/',
                                    nonce: 13469974270669794112).to_pkt
    }
    it 'should generate pkt' do
      expect(subject.bth).to eq('0b11090776657273696f6e0000000000670000000f798e7e7f1101000000000000000000cf31455900000000010000000000000000000000000000000000ffff7f000001479d010000000000000000000000000000000000ffff7f000001479d40abec703bf6eeba112f626974636f696e72623a302e312e302f00000000ff')
    end
  end

  describe '#pack_addr' do
    subject { Bitcoin::Message::Version.new.pack_addr('::ffff:a00:1:18333') }
    it 'should be parsed' do
      expect(subject.bth).to eq('010000000000000000000000000000000000ffff0a000001479d')
    end
  end

end