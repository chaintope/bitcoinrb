# encoding: ascii-8bit
require 'ipaddr'
module Bitcoin
  module Message

    # https://bitcoin.org/en/developer-reference#version
    class Version < Base

      COMMAND = 'version'

      attr_accessor :version
      attr_accessor :services
      attr_accessor :timestamp
      attr_accessor :local_addr
      attr_accessor :remote_addr
      attr_accessor :nonce
      attr_accessor :user_agent
      attr_accessor :start_height
      attr_accessor :relay

      def initialize(opts = {})
        @version = Bitcoin.chain_params.protocol_version
        @services = DEFAULT_SERVICE_FLAGS
        @timestamp = Time.now.to_i
        @local_addr = NetworkAddr.local_addr
        @remote_addr = NetworkAddr.local_addr
        @nonce = SecureRandom.random_number(0xffffffffffffffff)
        @user_agent = Bitcoin::Message::USER_AGENT
        @start_height = 0
        opts.each { |k, v| send "#{k}=", v }
        @relay = opts[:relay] || false
      end

      def self.parse_from_payload(payload)
        version, services, timestamp, local_addr, remote_addr, nonce, rest = payload.unpack('VQQa26a26Qa*')
        v = new
        v.version = version
        v.services = services
        v.timestamp = timestamp
        v.local_addr = NetworkAddr.parse_from_payload(local_addr)
        v.remote_addr = NetworkAddr.parse_from_payload(remote_addr)
        v.nonce = nonce
        user_agent, rest = unpack_var_string(rest)
        start_height, rest = rest.unpack('Va*')
        v.user_agent = user_agent
        v.start_height = start_height
        v.relay = v.unpack_relay_field(rest).first
        v
      end

      def to_payload
        [
          [version, services, timestamp].pack('VQQ'),
          local_addr.to_payload(true),
          remote_addr.to_payload(true),
          [nonce].pack('Q'),
          pack_var_string(user_agent),
          [start_height].pack('V'),
          pack_boolean(relay)
        ].join
      end

      def unpack_relay_field(payload)
        ( version >= 70001 && payload ) ? unpack_boolean(payload) : [ true, nil ]
      end

      # Check whether +service_flag+ support this version.
      # @param [Integer] service_flag the service flags.
      # @return [Boolean] whether support +service_flag+
      def support?(service_flag)
        (services & service_flag) != 0
      end

    end
  end
end