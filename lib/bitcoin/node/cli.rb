require 'net/http'
require 'thor'
require 'json'

module Bitcoin
  module Node

    class CLI < Thor

      class_option :network, aliases: '-n', default: :mainnet

      desc 'getblockchaininfo', 'Returns an object containing various state info regarding blockchain processing.'
      def getblockchaininfo
        request('getblockchaininfo')
      end

      desc 'stop', 'Stop Bitcoin server.'
      def stop
        request('stop')
      end

      desc 'getblockheader "hash" ( verbose )', 'If verbose is false, returns a string that is serialized, hex-encoded data for blockheader "hash". If verbose is true, returns an Object with information about blockheader <hash>.'
      def getblockheader(hash, verbose = true)
        verbose = verbose.is_a?(String) ? (verbose == 'true') : verbose
        request('getblockheader', hash, verbose)
      end

      desc 'getpeerinfo', 'Returns data about each connected network node as a json array of objects.'
      def getpeerinfo
        request('getpeerinfo')
      end

      desc 'decoderawtransaction "hexstring"', 'Return a JSON object representing the serialized, hex-encoded transaction.'
      def decoderawtransaction(hexstring)
        request('decoderawtransaction', hexstring)
      end

      desc 'decodescript "hexstring"', 'Decode a hex-encoded script.'
      def decodescript(hexstring)
        request('decodescript', hexstring)
      end

      # wallet cli

      desc 'sendrawtransaction', 'Submits raw transaction (serialized, hex-encoded) to local node and network.'
      def sendrawtransaction(hex_tx)
        request('sendrawtransaction', hex_tx)
      end

      desc 'createwallet "wallet_id"', 'Create new HD wallet. It returns an error if an existing wallet_id is specified. '
      def createwallet(wallet_id)
        request('createwallet', wallet_id)
      end

      desc 'listwallets', 'Returns a list of currently loaded wallets. For full information on the wallet, use "getwalletinfo"'
      def listwallets
        request('listwallets')
      end

      desc 'getwalletinfo', 'Returns an object containing various wallet state info.'
      def getwalletinfo
        request('getwalletinfo')
      end

      desc 'listaccounts', '[WIP]Returns Object that has account names as keys, account balances as values.'
      def listaccounts
        request('listaccounts')
      end

      desc 'encryptwallet "passphrase"', 'Encrypts the wallet with "passphrase". This is for first time encryption.After this, any calls that interact with private keys such as sending or signing will require the passphrase to be set prior the making these calls.'
      def encryptwallet(passhphrase)
        request('encryptwallet', passhphrase)
      end

      desc 'getnewaddress "account"', 'Returns a new Bitcoin address for receiving payments.'
      def getnewaddress(account)
        request('getnewaddress', account)
      end

      private

      def config
        opts = {}
        opts[:network] = options['network'] if options['network']
        @conf ||= Bitcoin::Node::Configuration.new(opts)
      end

      def request(command, *params)
        data = {
            :method => command,
            :params => params,
            :id => 'jsonrpc'
        }
        begin
          uri = URI.parse(config.server_url)
          http = Net::HTTP.new(uri.hostname, uri.port)
          http.use_ssl = uri.scheme === "https"
          request = Net::HTTP::Post.new('/')
          request.content_type = 'application/json'
          request.body = data.to_json
          response = http.request(request)
          body = response.body
          begin
          json = JSON.parse(body.to_str)
          puts JSON.pretty_generate(json)
          rescue Exception
            puts body.to_str
          end
        rescue Exception => e
          puts e.message
        end
      end

    end
  end
end
