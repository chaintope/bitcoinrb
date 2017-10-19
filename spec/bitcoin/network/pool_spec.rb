require 'spec_helper'

describe Bitcoin::Network::Pool do

  describe '#allocate_peer_id' do
    subject {
      pool = Bitcoin::Network::Pool.new(create_test_chain)
      peer1 = Bitcoin::Network::Peer.new('192.168.0.1', 18333, pool)
      peer2 = Bitcoin::Network::Peer.new('192.168.0.2', 18333, pool)
      peer3 = Bitcoin::Network::Peer.new('192.168.0.3', 18333, pool)
      allow(peer1).to receive(:start_block_header_download).and_return(nil)
      allow(peer2).to receive(:start_block_header_download).and_return(nil)
      allow(peer3).to receive(:start_block_header_download).and_return(nil)
      pool.handle_new_peer(peer1)
      pool.handle_new_peer(peer2)
      pool.handle_new_peer(peer3)
      pool
    }
    it 'should allocate peer id' do
      expect(subject.peers.size).to eq(3)
      expect(subject.peers[0].id).to eq(0)
      expect(subject.peers[1].id).to eq(1)
      expect(subject.peers[2].id).to eq(2)
    end
  end

end