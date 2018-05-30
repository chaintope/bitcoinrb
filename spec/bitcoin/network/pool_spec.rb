require 'spec_helper'

describe Bitcoin::Network::Pool do
  let(:chain) { create_test_chain }
  let(:pool) { Bitcoin::Network::Pool.new(node_mock, chain, configuration) }
  let(:node_mock) { double('node mock') }
  let(:configuration) { Bitcoin::Node::Configuration.new }
  let(:peer1) { Bitcoin::Network::Peer.new('192.168.0.1', 18333, pool, configuration) }
  let(:peer2) { Bitcoin::Network::Peer.new('192.168.0.2', 18333, pool, configuration) }
  let(:peer3) { Bitcoin::Network::Peer.new('192.168.0.3', 18333, pool, configuration) }

  before do
    allow(node_mock).to receive(:wallet).and_return(nil)
    allow(peer1).to receive(:start_block_header_download).and_return(nil)
    allow(peer2).to receive(:start_block_header_download).and_return(nil)
    allow(peer3).to receive(:start_block_header_download).and_return(nil)
    pool.handle_new_peer(peer1)
    pool.handle_new_peer(peer2)
    pool.handle_new_peer(peer3)
  end

  after { chain.db.close }

  describe '#allocate_peer_id' do
    subject { pool }

    it 'should allocate peer id' do
      expect(subject.peers.size).to eq(3)
      expect(subject.peers[0].id).to eq(0)
      expect(subject.peers[1].id).to eq(1)
      expect(subject.peers[2].id).to eq(2)
    end

    context 'when allocate again after disconnect' do
      subject {
        pool.started = true
        allow(pool).to receive(:connect).and_return(nil)
        pool.handle_close_peer(peer2)
        pool.handle_new_peer(peer2)
        pool
      }
      it 'should allocate peer id' do
        expect(subject.peers.size).to eq(3)
        expect(subject.peers[0].id).to eq(0)
        expect(subject.peers[1].id).to eq(2)
        expect(subject.peers[2].id).to eq(1)
      end
    end
  end

  describe '#handle_close_peer' do
    subject do
      pool.started = true
      allow(pool).to receive(:connect).and_return(nil)
      pool.handle_close_peer(peer2)
      pool
    end

    it { expect { subject }.to change(pool.peers, :size).from(3).to(2) }
    it { expect(subject.peers[0].host).to eq '192.168.0.1' }
    it { expect(subject.peers[1].host).to eq '192.168.0.3' }
  end
end
