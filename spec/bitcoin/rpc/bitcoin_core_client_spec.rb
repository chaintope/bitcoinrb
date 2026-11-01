require 'spec_helper'

describe Bitcoin::RPC::BitcoinCoreClient do

  let!(:client) { 
    # for Bitcoin::RPC::BitcoinCoreClient#initialize
    stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': 'rpccommand' }))
    Bitcoin::RPC::BitcoinCoreClient.new(config)
  }
  let(:config) { {
    schema: 'http',
    host: 'localhost',
    port: 18332,
    user: 'xxx',
    password: 'yyy'
  } }
  let(:server_url) { "#{config[:schema]}://#{config[:host]}:#{config[:port]}" }

  describe '#{rpccommand}' do
    it 'should return rpc response' do
      stub_request(:post, server_url).to_return(
        body: JSON.generate({ 'result': 'RESPONSE' })
      )
      expect(client.rpccommand).to eq('RESPONSE')
    end
    
    context 'error on requesting' do
      it 'should raise error' do
        stub_request(:post, server_url).to_raise(StandardError.new('ERROR'))
        expect { client.rpccommand }.to raise_error(StandardError, 'ERROR')
      end
    end

    context 'server responded with error' do
      it 'should raise Bitcoin::RPC::Error with the code and message of the response' do
        stub_request(:post, server_url).to_return(status: 500, body: JSON.generate({ 'error': { 'code': -8, 'message': 'RPC ERROR' }, 'result': nil }))
        expect { client.rpccommand }.to raise_error(Bitcoin::RPC::Error, 'RPC ERROR') do |e|
          expect(e.code).to eq(-8)
          expect(e.http_status).to eq(500)
          expect(e.data).to eq({ 'code' => -8, 'message' => 'RPC ERROR' })
          expect(e).to be_a(RuntimeError) # as the error raised before Bitcoin::RPC::Error was
        end
        # A code given as a string is read as the integer it holds.
        stub_request(:post, server_url).to_return(body: JSON.generate({ 'error': { 'code': '-1', 'message': 'RPC ERROR' } }))
        expect { client.rpccommand }.to raise_error(Bitcoin::RPC::Error) { |e| expect(e.code).to eq(-1) }
      end

      it 'should raise Bitcoin::RPC::Error for an answer which is not a JSON-RPC response' do
        stub_request(:post, server_url).to_return(status: [401, 'Unauthorized'], body: '')
        expect { client.rpccommand }.to raise_error(Bitcoin::RPC::Error, 'Bitcoin Core answered HTTP 401 Unauthorized without a JSON-RPC response.') do |e|
          expect(e.code).to be_nil
          expect(e.http_status).to eq(401)
        end
        stub_request(:post, server_url).to_return(body: '[1]')
        expect { client.rpccommand }.to raise_error(Bitcoin::RPC::Error, /not a JSON-RPC response/)
      end

      it 'should raise Bitcoin::RPC::Error when the response answers another request' do
        stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': 'x', 'error': nil, 'id': 'other' }))
        expect { client.rpccommand }.to raise_error(Bitcoin::RPC::Error, /is not the id of the request/)
      end

      it 'should accept the response which echoes the id of the request' do
        stub_request(:post, server_url).to_return do |request|
          { body: JSON.generate({ 'result': 'x', 'error': nil, 'id': JSON.parse(request.body)['id'] }) }
        end
        expect(client.rpccommand).to eq('x')
      end
    end

    context 'contains float value' do
      it 'should convert string value' do
        stub_request(:post, server_url).to_return(
            body: JSON.generate({ 'result': {'amount': 0.08495981} })
        )
        expect(client.rpc_command['amount']).to eq("0.08495981")
      end
    end

    context 'contains escaped unicode' do
      it 'should unescape it' do
        stub_request(:post, server_url).to_return(
            body: '{"result":{"label":"\u3042\u00e9"},"error":null}'
        )
        expect(client.rpc_command['label']).to eq("あé")
      end

      # An escaped double quote must stay inside the string it belongs to. Unescaping it before
      # JSON.parse lets a value close its own string and inject arbitrary JSON into the result.
      it 'should not let an escaped quote break out of the string' do
        stub_request(:post, server_url).to_return(
            body: '{"result":{"label":"a\u0022,\u0022result\u0022:\u0022INJECTED"},"error":null}'
        )
        expect(client.rpc_command).to eq({ 'label' => 'a","result":"INJECTED' })
      end
    end

    context 'wallet is specified in config' do
      let(:config) { super().merge({ wallet: 'mywallet' }) }
      let(:server_url) { "#{config[:schema]}://#{config[:host]}:#{config[:port]}/wallet/#{config[:wallet]}" }
      it 'should have wallet name in the path like "/wallet/[wallet_name]"' do
        assert_requested(:post, server_url)
        client.rpc_command
      end
    end
  end
  
  describe '#method_missing' do
    it 'should return rpc response' do
      stub_request(:post, server_url).to_return(
        body: JSON.generate({ 'result': 'RESPONSE' })
      )
      expect(client.rpc_command).to eq('RESPONSE')
    end
    
    context 'method undefined' do
      it 'should raise error' do
        expect { client.undefined_method }.to raise_error(NoMethodError)
        expect { client.undefinedmethod }.to raise_error(NoMethodError)
      end
    end

    context 'command with arguments' do
      let!(:client) {
        stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': "getblockhash\nrpccommand" }))
        Bitcoin::RPC::BitcoinCoreClient.new(config)
      }
      it 'should pass the arguments as the params array, not nested in another array' do
        stub_request(:post, server_url).with(body: hash_including('method' => 'getblockhash', 'params' => [1])).
          to_return(body: JSON.generate({ 'result': 'HASH' }))
        expect(client.get_block_hash(1)).to eq('HASH')
        expect(client.getblockhash(1)).to eq('HASH')
        expect(client.respond_to?(:get_block_hash)).to be true
        expect(client.respond_to?(:get_block_hush)).to be false
      end
    end
  end

  describe 'credentials and wallet in the request' do
    let(:config) { super().merge(user: 'alice', password: 'p@ss/w#rd%41 x') }

    it 'should send the credentials in the Authorization header, whatever characters they contain' do
      stub_request(:post, server_url).with(basic_auth: ['alice', 'p@ss/w#rd%41 x']).to_return(body: JSON.generate({ 'result': 'OK' }))
      expect(client.rpccommand).to eq('OK')
      assert_requested(:post, server_url, basic_auth: ['alice', 'p@ss/w#rd%41 x'], times: 2) # help + rpccommand
    end

    context 'wallet name with characters which are not allowed in a path' do
      let(:config) { super().merge(wallet: 'my wallet/1') }
      let(:server_url) { "http://localhost:18332/wallet/my%20wallet%2F1" }
      it 'should percent-encode the wallet name' do
        stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': 'OK' }))
        expect(client.rpccommand).to eq('OK')
      end
    end
  end

end
