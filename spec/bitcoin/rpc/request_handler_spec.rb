require 'spec_helper'

describe Bitcoin::RPC::RequestHandler do

  class HandlerMock
    include Bitcoin::RPC::RequestHandler
    attr_reader :node
    def initialize(node)
      @node = node
    end
  end

  let(:chain) { load_chain_mock }
  subject {
    node_mock = double('node mock')
    allow(node_mock).to receive(:chain).and_return(chain)
    allow(node_mock).to receive(:pool).and_return(load_pool_mock(node_mock.chain))
    HandlerMock.new(node_mock)
  }
  after { chain.db.close }

  describe '#getblockchaininfo' do
    it 'should return chain info' do
      result = subject.getblockchaininfo
      expect(result[:chain]).to eq('testnet')
      expect(result[:headers]).to eq(1210339)
      expect(result[:bestblockhash]).to eq('00000000ecae98e551fde86596f9e258d28edefd956f1e6919c268332804b668')
      expect(result[:mediantime]).to eq(1508126989)
    end
  end

  describe '#getblockheader' do
    it 'should return header info' do
      result = subject.getblockheader('00000000fb0350a72d7316a2006de44e74c16b56843a29bd85e0535d71edbc5b', true)
      expect(result[:hash]).to eq('00000000fb0350a72d7316a2006de44e74c16b56843a29bd85e0535d71edbc5b')
      expect(result[:height]).to eq(1210337)
      expect(result[:version]).to eq(536870912)
      expect(result[:versionHex]).to eq('20000000')
      expect(result[:merkleroot]).to eq('ac92cbb5ccd160f9b474f27a1ed50aa9f503b4d39c5acd7f24ef0a6a0287c7c6')
      expect(result[:time]).to eq(1508130596)
      expect(result[:mediantime]).to eq(1508125317)
      expect(result[:nonce]).to eq(1647419287)
      expect(result[:bits]).to eq('1d00ffff')
      expect(result[:previousblockhash]).to eq('00000000cd01007346f9a3d384a507f97afb164c057bcd1694ca20bb3302bb8d')
      expect(result[:nextblockhash]).to eq('000000008f71fb3f76a19075987a5d5653efce9bab90474497c9e1151ac94b69')
      header = subject.getblockheader('00000000fb0350a72d7316a2006de44e74c16b56843a29bd85e0535d71edbc5b', false)
      expect(header).to eq('000000208dbb0233bb20ca9416cd7b054c16fb7af907a584d3a3f946730001cd00000000c6c787026a0aef247fcd5a9cd3b403f5a90ad51e7af274b4f960d1ccb5cb92ac243fe459ffff001d979f3162')
    end
  end

  describe '#getpeerinfo' do
    it 'should return connected peer info' do
      result = subject.getpeerinfo
      expect(result.length).to eq(2)
      expect(result[0][:id]). to eq(1)
      expect(result[0][:addr]). to eq('192.168.0.1:18333')
      expect(result[0][:addrlocal]). to eq('192.168.0.3:18333')
      expect(result[0][:services]). to eq('000000000000000c')
      expect(result[0][:relaytxes]). to be true
      expect(result[0][:lastsend]). to eq(1508305982)
      expect(result[0][:lastrecv]). to eq(1508305843)
      expect(result[0][:bytessent]). to eq(31298)
      expect(result[0][:bytesrecv]). to eq(1804)
      expect(result[0][:conntime]). to eq(1508305774)
      expect(result[0][:pingtime]). to eq(0.593433)
      expect(result[0][:minping]). to eq(0.593433)
      expect(result[0][:version]). to eq(70015)
      expect(result[0][:subver]). to eq('/Satoshi:0.14.1/')
      expect(result[0][:inbound]). to be false
      expect(result[0][:startingheight]). to eq(1210488)
      expect(result[0][:best_hash]). to eq(-1)
      expect(result[0][:best_height]). to eq(-1)
    end
  end

  private

  def load_entry(payload, height)
    header = Bitcoin::BlockHeader.parse_from_payload(payload.htb)
    Bitcoin::Store::ChainEntry.new(header, height)
  end

  def load_chain_mock
    chain_mock = create_test_chain
    latest_entry = load_entry('00000020694bc91a15e1c997444790ab9bceef53565d7a987590a1763ffb718f0000000024fe00f0aa7507e54a4a586be1ea7c7d9e077e049e08a8e397da4a4c1a02d14b8d48e459ffff001dc735461c', 1210339)
    allow(chain_mock).to receive(:latest_block).and_return(latest_entry)
    # recent 11 block
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000ecae98e551fde86596f9e258d28edefd956f1e6919c268332804b668').and_return(latest_entry)
    allow(chain_mock).to receive(:find_entry_by_hash).with('000000008f71fb3f76a19075987a5d5653efce9bab90474497c9e1151ac94b69').and_return(load_entry('000000205bbced715d53e085bd293a84566bc1744ee46d00a216732da75003fb00000000a0f199af05f22972246d9a380130e498f03df945f482718ee0787ca6dad24808d843e459ffff001d983d2926', 1210338))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000fb0350a72d7316a2006de44e74c16b56843a29bd85e0535d71edbc5b').and_return(load_entry('000000208dbb0233bb20ca9416cd7b054c16fb7af907a584d3a3f946730001cd00000000c6c787026a0aef247fcd5a9cd3b403f5a90ad51e7af274b4f960d1ccb5cb92ac243fe459ffff001d979f3162', 1210337))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000cd01007346f9a3d384a507f97afb164c057bcd1694ca20bb3302bb8d').and_return(load_entry('0000002080244a62f307b3b885a253a3614a3fe6e78de3895512d6e8d44d65aa00000000d1574450981c63e36214035a38aeb1d9fa582bac452ac178c75e9dd8efdf9fd9733ae459ffff001d051759a0', 1210336))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000aa654dd4e8d6125589e38de7e63f4a61a353a285b8b307f3624a2480').and_return(load_entry('00000020426410aa5fcdca74b3598160417f9e2c986edc8fb8633b7f6000000000000000c928ae0f8ed48979bfbdf851ca8a49198731b8e8830139217043e004ce76881bc235e459ffff001d6496f136', 1210335))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000000000607f3b63b88fdc6e982c9e7f41608159b374cacd5faa106442').and_return(load_entry('00000020f91653ebd7535d498a3cd62db46e939b676a04ae6a35e33f418c0e1800000000b47bfeae2b2201b7b86f34e948099788cfd5ae7fdf1b8fe51bb2651a85946a510d31e45980e17319eee6f292', 1210334))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000180e8c413fe3356aae046a679b936eb42dd63c8a495d53d7eb5316f9').and_return(load_entry('00000020cd931c47b454b2d67a99e380cd051f33d316263548748bdee5a6b3ec0000000035c824c91f310d2b19b772fba5f0fcd9e9e8d0f189e47f5064fc7770ef0957bc362fe459ffff001d13beb4a8', 1210333))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000ecb3a6e5de8b7448352616d3331f05cd80e3997ad6b254b4471c93cd').and_return(load_entry('00000020949c2f5f9083dd4ec45b2c26c28ca701c0f640d62e52551b4b000000000000009305fca54fae340d5b2c9dceb8a559443d5cfb44504bc939820984cbb26b1e2d852ae459ffff001d6babc9be', 1210332))
    allow(chain_mock).to receive(:find_entry_by_hash).with('000000000000004b1b55522ed640f6c001a78cc2262c5bc44edd83905f2f9c94').and_return(load_entry('0000002046194705aa7b0aca636c5a45a3c8857640cddaaab27e44cbc43f5d7f00000000439414cce8f17b94cf2ef654cc96f85e87b5f0a5c615ae474151e02b8ea9f3cdd125e45980e17319eb2ea570', 1210331))
    allow(chain_mock).to receive(:find_entry_by_hash).with('000000007f5d3fc4cb447eb2aadacd407685c8a3455a6c63ca0a7baa05471946').and_return(load_entry('000000206984d6f872f6499432f66d5bb8eec0f30248e79483382af621000000000000007246d107520e77f6b08c8d74ac0b06f4a8e229070ff95dc07b1fc477a68a0b0b7421e459ffff001d0e7bcc94', 1210330))
    allow(chain_mock).to receive(:find_entry_by_hash).with('0000000000000021f62a388394e74802f3c0eeb85b6df6329449f672f8d68469').and_return(load_entry('00000020f1bd62cf4502b7f88eeae4bb8cf2caa3615caac0dde9bf064994e4350000000067f8d203143e834fd6572aef4bc961b4f9ef4d18b63d6a73ed6342403406e815bf1ce45980e173198907b9ad', 1210329))
    allow(chain_mock).to receive(:find_entry_by_hash).with('0000000035e4944906bfe9ddc0aa5c61a3caf28cbbe4ea8ef8b70245cf62bdf1').and_return(load_entry('04000000587b7ec2f7b00aecadc816f74c4734f5d3b57744fa98061b2452245300000000acf407f07491f3c7e326702c84c2319b98989b1d287e612385b35f01bb49a29e7518e459ffff001d40cce489', 1210328))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000532452241b0698fa4477b5d3f534474cf716c8adec0ab0f7c27e7b58').and_return(load_entry('00000020b5b07293524eece44221a180a6c67538b5685b474015993ea9422e7600000000ae01949e6bac5a828216d89ea91fc7dfe0bee5488644c7f228e15e0b87b3322fc113e459ffff001d5ef80539', 1210327))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00000000762e42a93e991540475b68b53875c6a680a12142e4ec4e529372b0b5').and_return(load_entry('00000020fbf65774599e7bf53452a61f0784f30159ffa98e4bfa7091624bb3760000000012e5e283f096b9c14669c38049f4012462f48adb7d7d5e6dc32f3576688ef5480c0fe459ffff001dabe97de2', 1210326))

    # previous block
    allow(chain_mock).to receive(:next_hash).with('00000000fb0350a72d7316a2006de44e74c16b56843a29bd85e0535d71edbc5b').and_return('000000008f71fb3f76a19075987a5d5653efce9bab90474497c9e1151ac94b69')
    chain_mock
  end

  def load_pool_mock(chain)
    conn1 = double('connection_mock1')
    conn2 = double('connection_mock1')
    allow(conn1).to receive(:version).and_return(Bitcoin::Message::Version.new(
        version: 70015, user_agent: '/Satoshi:0.14.1/', start_height: 1210488,
        remote_addr: '192.168.0.3:60519', services: 12
    ))
    allow(conn2).to receive(:version).and_return(Bitcoin::Message::Version.new)

    configuration = Bitcoin::Node::Configuration.new(network: :testnet)
    pool = Bitcoin::Network::Pool.new(chain, configuration)

    peer1 =Bitcoin::Network::Peer.new('192.168.0.1', 18333, pool)
    peer1.id = 1
    peer1.last_send = 1508305982
    peer1.last_recv = 1508305843
    peer1.bytes_sent = 31298
    peer1.bytes_recv = 1804
    peer1.conn_time = 1508305774
    peer1.last_ping = 1508386048
    peer1.last_pong = 1508979481

    allow(peer1).to receive(:conn).and_return(conn1)
    pool.peers << peer1

    peer2 =Bitcoin::Network::Peer.new('192.168.0.2', 18333, pool)
    peer2.id = 2
    allow(peer2).to receive(:conn).and_return(conn2)
    pool.peers << peer2

    pool
  end

end