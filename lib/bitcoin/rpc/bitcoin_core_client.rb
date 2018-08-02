require 'rest-client'

module Bitcoin
  module RPC

    # Client implementation for RPC to Bitcoin Core.
    #
    # [Usage]
    # config = {schema: 'http', host: 'localhost', port: 18332, user: 'xxx', password: 'yyy'}
    # client = Bitcoin::RPC::BitcoinCoreClient.new(config)
    #
    # You can execute the CLI command supported by Bitcoin Core as follows:
    #
    # client.listunspent
    # client.getblockchaininfo
    #
    class BitcoinCoreClient

      attr_reader :config

      # @param [Hash] config a configuration required to connect to Bitcoin Core.
      def initialize(config)
        @config = config

        commands = request(:help).split("\n").inject([]) do |memo_ary, line|
          if !line.empty? && !line.start_with?('==')
            memo_ary << line.split(' ').first.to_sym
          end
          memo_ary
        end
        BitcoinCoreClient.class_eval do
          commands.each do |command|
            define_method(command) do |*params|
              request(command, *params)
            end
          end
        end
      end

      private

      def server_url
        url = "#{config[:schema]}://#{config[:user]}:#{config[:password]}@#{config[:host]}:#{config[:port]}"
        if !config[:wallet].nil? && !config[:wallet].empty?
          url += "/wallet/#{config[:wallet]}"
        end
        url
      end

      def request(command, *params)
        data = {
            :method => command,
            :params => params,
            :id => 'jsonrpc'
        }
        post(server_url, @config[:timeout], @config[:open_timeout], data.to_json, content_type: :json) do |respdata, request, result|
          raise result.message if !result.kind_of?(Net::HTTPSuccess) && respdata.empty?
          response = JSON.parse(respdata.gsub(/\\u([\da-fA-F]{4})/) { [$1].pack('H*').unpack('n*').pack('U*').encode('ISO-8859-1').force_encoding('UTF-8') })
          raise response['error'] if response['error']
          response['result']
        end
      end

      def post(url, timeout, open_timeout, payload, headers={}, &block)
        RestClient::Request.execute(method: :post, url: url, timeout: timeout,
                                    open_timeout: open_timeout, payload: payload, headers: headers, &block)
      end

    end

  end
end