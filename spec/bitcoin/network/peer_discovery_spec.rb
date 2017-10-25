require 'spec_helper'

describe Bitcoin::Network::PeerDiscovery do

  describe '#peers' do
    let(:dns_seeds) { [] }
    let(:connect) { [] }
    subject {
      peer_discovery = Bitcoin::Network::PeerDiscovery.new
      allow(peer_discovery).to receive(:dns_seeds).and_return(dns_seeds)
      allow(peer_discovery).to receive(:seeds).and_return(connect)
      peer_discovery
    }
    context 'dns_seeds is empty' do
      context 'connect nodes is empty' do
        it 'should be empty' do
          expect(subject.peers).to eq []
        end
      end
      context 'one connect node exists' do
        let(:connect) { ['123.123.123.123'] }
        it 'should return one node' do
          expect(subject.peers).to eq ['123.123.123.123']
        end
      end
    end
  end
end
