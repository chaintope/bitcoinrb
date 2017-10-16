require 'inifile'

module Bitcoin
  module Node
    class Configuration

      attr_reader :conf

      def initialize(opts = {})
        # TODO apply configuration file.
        @conf = IniFile.load("#{Bitcoin.base_dir}/bitcoinrb.conf").to_h
        @conf.merge!(opts)
        @conf[:network] = :mainnet unless @conf[:network]
        Bitcoin.chain_params = @conf[:network]
      end

      def host
        'localhost'
      end

      def port
        Bitcoin.chain_params.default_port - 1
      end

      def server_url
        "http://#{host}:#{port}"
      end

    end
  end
end
