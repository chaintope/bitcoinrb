require 'spec_helper'

describe Bitcoin::Network::Peer do

  class ConnectionMock
    attr_accessor :version, :sendheaders, :fee_rate
  end

  let(:chain) { create_test_chain }
  subject {
    chain_mock = double('chain mock')
    node_mock = double('node mock')
    configuration = Bitcoin::Node::Configuration.new(network: :testnet)
    peer = Bitcoin::Network::Peer.new('210.196.254.100', 18333,
                                      Bitcoin::Network::Pool.new(node_mock, chain, configuration), configuration)
    peer.conn = ConnectionMock.new
    allow(peer).to receive(:chain).and_return(chain_mock)
    peer
  }
  after { chain.db.close }

  describe '#support_witness?' do
    context 'before handshake' do
      it 'should be false' do
        expect(subject.support_witness?).to be false
        expect(subject.local_version.relay).to be false # spv set relay flag to false.
      end
    end

    context 'non segwit peer' do
      before {
        subject.conn.version = Bitcoin::Message::Version.new(services: Bitcoin::Message::SERVICE_FLAGS[:none])
      }
      it 'should be false' do
        expect(subject.support_witness?).to be false
      end
    end

    context 'segwit peer' do
      before {
        subject.conn.version = Bitcoin::Message::Version.new
      }
      it 'should be true' do
        expect(subject.support_witness?).to be true
      end
    end
  end

  describe '#support_cmpct?' do
    context 'remote peer dose not support' do
      it 'should be false' do
        # not support version
        subject.conn.version = Bitcoin::Message::Version.new(version: 70013)
        expect(subject.support_cmpct?).to be false
        # local support segwit, but remote dose not support segwit
        subject.conn.version = Bitcoin::Message::Version.new(version: 70015, services: Bitcoin::Message::SERVICE_FLAGS[:network])
        expect(subject.support_cmpct?).to be false
        # remote's version dose not support witness block
        subject.conn.version = Bitcoin::Message::Version.new(version: 70014, services: Bitcoin::Message::SERVICE_FLAGS[:witness])
        expect(subject.support_cmpct?).to be false
      end
    end

    context 'remote peer support' do
      it 'should be true' do
        # local dose not supports segwit, and remote too.
        subject.local_version = Bitcoin::Message::Version.new(version: 70014, services: Bitcoin::Message::SERVICE_FLAGS[:network])
        subject.conn.version = Bitcoin::Message::Version.new(version: 70014, services: Bitcoin::Message::SERVICE_FLAGS[:network])
        expect(subject.support_cmpct?).to be true
        # local and remote supports compact witness.
        subject.local_version = Bitcoin::Message::Version.new
        subject.conn.version = Bitcoin::Message::Version.new(version: 70015, services: Bitcoin::Message::SERVICE_FLAGS[:witness])
        expect(subject.support_cmpct?).to be true
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
    it 'should call update with :header' do
      listener = double('listener')
      expect(listener).to receive(:update).with(:header, {hash:-1, height: -1})
      subject.pool.add_observer(listener)
      subject.handle_headers(Bitcoin::Message::Headers.new)
    end
  end

  describe '#handle_block_inv' do
    it 'should send getdadta message' do
      hash = '00000000e0f952393cbb1874aa4ee18e81eaa057292a22e822eb9c80eed37dc8'
      inventory = Bitcoin::Message::Inventory.new( 3, hash)
      expect(subject.conn).not_to receive(:send_message).with(
          custom_object(Bitcoin::Message::GetData, inventories: [inventory]))
      subject.handle_block_inv([hash])
    end
  end

  describe '#handler_tx' do
    it 'should call update with :tx' do
      listener = double('listener')
      payload = "0100000001d58708dc89a5649c41985d2a2c9b83b641f7955b37454e177813c2262189b342010000006a47304402200958e5ef78bf22fd6335a4335cfe4bf2e5199cab79e2174a272a9f768a0eb36c02204a602e72d3a158e9e9217f690d7837e3f1cdc8e5f2ad0fcfbd230a351889eb5f0121033d5c2875c9bd116875a71a5db64cffcb13396b163d039b1d9327824891804334ffffffff02d2020000000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac2672ea04000000001976a914990ef60d63b5b5964a1c2282061af45123e93fcb88ac00000000".htb
      tx = Bitcoin::Message::Tx.new(Bitcoin::Tx.parse_from_payload(payload))
      expect(listener).to receive(:update).with(:tx, tx)
      subject.pool.add_observer(listener)
      subject.handle_tx(tx)
    end
  end
end
