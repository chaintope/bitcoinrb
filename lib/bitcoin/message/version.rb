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

      # The part every version message has: version, services, timestamp and the receiving address.
      MIN_PAYLOAD_SIZE = 4 + 8 + 8 + 26

      # Parse a version message. As Bitcoin Core does, the sending address and nonce, the user agent, the
      # start height and the relay flag are each read only when the payload still has data, so a message
      # from an old protocol version which stops early is accepted with the remaining fields empty.
      def self.parse_from_payload(payload)
        raise Bitcoin::Message::Error, 'Version payload is too short.' if payload.bytesize < MIN_PAYLOAD_SIZE
        version, services, timestamp, local_addr, rest = payload.unpack('VQ<Q<a26a*')
        v = new(remote_addr: NetworkAddr.new(time: nil), nonce: 0, user_agent: '', start_height: 0)
        v.version = version
        v.services = services
        v.timestamp = timestamp
        v.local_addr = NetworkAddr.parse_from_payload(local_addr)
        unless rest.empty?
          raise Bitcoin::Message::Error, 'Version payload is truncated.' if rest.bytesize < 26 + 8
          remote_addr, nonce, rest = rest.unpack('a26Q<a*')
          v.remote_addr = NetworkAddr.parse_from_payload(remote_addr)
          v.nonce = nonce
        end
        v.user_agent, rest = unpack_var_string(rest) unless rest.empty?
        unless rest.empty?
          raise Bitcoin::Message::Error, 'Version payload is truncated.' if rest.bytesize < 4
          v.start_height, rest = rest.unpack('Va*')
        end
        v.relay = v.unpack_relay_field(rest).first
        v
      end

      def to_payload
        [
          [version, services, timestamp].pack('VQ<Q<'),
          local_addr.to_payload(true),
          remote_addr.to_payload(true),
          [nonce].pack('Q<'),
          pack_var_string(user_agent),
          [start_height].pack('V'),
          pack_boolean(relay)
        ].join
      end

      def unpack_relay_field(payload)
        ( version >= 70001 && payload && !payload.empty? ) ? unpack_boolean(payload) : [ true, nil ]
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