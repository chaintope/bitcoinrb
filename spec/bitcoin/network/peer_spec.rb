require 'spec_helper'

describe Bitcoin::Network::Peer do

  class ConnectionMock
    attr_accessor :version, :sendheaders, :fee_rate
  end

  subject {
    chain_mock = double('chain mock')
    peer = Bitcoin::Network::Peer.new('210.196.254.100', 18333, Bitcoin::Network::Pool.new(create_test_chain))
    peer.conn = ConnectionMock.new
    allow(peer).to receive(:chain).and_return(chain_mock)
    peer
  }

  describe '#support_segwit?' do
    context 'before handshake' do
      it 'should be false' do
        expect(subject.support_segwit?).to be false
      end
    end

    context 'non segwit peer' do
      before {
        subject.conn.version = Bitcoin::Message::Version.new(services: Bitcoin::Message::SERVICE_FLAGS[:none])
      }
      it 'should be false' do
        expect(subject.support_segwit?).to be false
      end
    end

    context 'segwit peer' do
      before {
        subject.conn.version = Bitcoin::Message::Version.new
      }
      it 'should be true' do
        expect(subject.support_segwit?).to be true
      end
    end

  end

  describe '#to_network_addr' do
    before {
      opts = {version:70015, services: 13, timestamp: 1507879363, local_addr: "0.0.0.0:0", remote_addr: "94.130.106.254:63446", nonce: 1561841459448609851, user_agent: "/Satoshi:0.14.2/", start_height: 1210117, relay: true}
      subject.conn.version = Bitcoin::Message::Version.new(opts)
    }
    it 'should be generate' do
      network_addr = subject.to_network_addr
      expect(network_addr.ip).to eq('210.196.254.100')
      expect(network_addr.port).to eq(18333)
      expect(network_addr.services).to eq(13)
      expect(network_addr.time).to eq(1507879363)
    end
  end

  describe '#handle_headers' do
    context 'IBD finished' do
      it 'should not send next getheaders' do
        expect(subject).not_to receive(:start_block_header_download)
        subject.handle_headers(Bitcoin::Message::Headers.new)
      end
    end
  end

end
