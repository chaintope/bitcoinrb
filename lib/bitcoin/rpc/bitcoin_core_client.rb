require 'net/http'

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

      # Whether a Ruby-like method name such as get_block_hash maps to an RPC command.
      def respond_to_missing?(name, include_private = false)
        (name.to_s.include?('_') && respond_to?(name.to_s.delete('_').to_sym)) || super
      end

      private

      # The URL of the RPC endpoint, without the credentials. These go in the Authorization header,
      # so a password with characters such as '@', '/' or '#' cannot change the host or the path.
      # @return [URI::HTTP]
      def server_uri
        path = '/'
        if !config[:wallet].nil? && !config[:wallet].empty?
          path = "/wallet/#{percent_encode(config[:wallet])}"
        end
        klass = config[:schema].to_s == 'https' ? URI::HTTPS : URI::HTTP
        klass.build(host: config[:host], port: config[:port], path: path)
      end

      # Percent-encode every character of +str+ which is not unreserved in a URL path.
      def percent_encode(str)
        str.to_s.b.gsub(/[^A-Za-z0-9\-._~]/) { |c| format('%%%02X', c.ord) }
      end

      def request(command, *params)
        data = {
            :method => command,
            :params => params,
            :id => 'jsonrpc'
        }
        uri = server_uri
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = uri.scheme == 'https'
        request = Net::HTTP::Post.new(uri.path)
        request.basic_auth(config[:user].to_s, config[:password].to_s)
        request.content_type = 'application/json'
        request.body = data.to_json
        response = http.request(request)
        # Unescape \uXXXX with JSON.parse itself. Doing it beforehand lets a " contained in
        # a string value close that string and inject arbitrary JSON into the parsed result.
        json_data = JSON.parse(response.body)
        response = convert_floats_to_strings(json_data)
        raise response['error'].to_json if response['error']
        response['result']
      end
      
      # Call CLI command on Ruby-like method names.
      # e.g. generate_to_address, send_to_address, get_wallet_info
      def method_missing(name, *args)
        command = name.to_s.delete('_').to_sym
        if name.to_s.include?('_') && respond_to?(command)
          send(command, *args)
        else
          super
        end
      end

      # Convert float value
      def convert_floats_to_strings(obj)
        case obj
        when Float
          obj.to_s
        when Hash
          obj.transform_values { |v| convert_floats_to_strings(v) }
        when Array
          obj.map { |item| convert_floats_to_strings(item) }
        else
          obj
        end
      end
    end
  end
end