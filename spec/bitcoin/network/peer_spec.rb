require 'spec_helper'

describe Bitcoin::Network::Peer do

  class ConnectionMock
    attr_accessor :version, :sendheaders, :fee_rate
  end

  subject {
    peer = Bitcoin::Network::Peer.new('127.0.0.1', 18332, Bitcoin::Network::Pool.new(create_test_chain))
    peer.conn = ConnectionMock.new
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

end