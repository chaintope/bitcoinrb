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
        @local_addr = "127.0.0.1:#{Bitcoin.chain_params.default_port}"
        @remote_addr = "127.0.0.1:#{Bitcoin.chain_params.default_port}"
        @nonce = SecureRandom.random_number(0xffffffffffffffff)
        @user_agent = Bitcoin::Message::USER_AGENT
        @start_height = 0
        @relay = true
        opts.each { |k, v| send "#{k}=", v }
      end

      def self.parse_from_payload(payload)
        version, services, timestamp, remote_addr, local_addr, nonce, rest = payload.unpack('VQQa26a26Qa*')
        v = new
        v.version = version
        v.services = services
        v.timestamp = timestamp
        v.remote_addr = v.unpack_addr(remote_addr)
        v.local_addr = v.unpack_addr(local_addr)
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
          pack_addr(local_addr),
          pack_addr(remote_addr),
          [nonce].pack('Q'),
          pack_var_string(user_agent),
          [start_height].pack('V'),
          pack_boolean(relay)
        ].join
      end

      def pack_addr(addr)
        separator = addr.rindex(':')
        ip = addr[0...separator]
        port = addr[separator + 1..-1].to_i
        ip_addr = IPAddr.new(ip)
        ip_addr = ip_addr.ipv4_mapped if ip_addr.ipv4?
        [1].pack('Q') << ip_addr.hton << [port].pack('n')
        # [[1].pack('Q'), "\x00" * 10, "\xFF\xFF", sockaddr[4...8], sockaddr[2...4]].join
      end

      def unpack_addr(addr)
        host, port = addr.unpack('x8x12a4n')
        "#{host.unpack('C*').join('.')}:#{port}"
      end

      def unpack_relay_field(payload)
        ( version >= 70001 && payload ) ? unpack_boolean(payload) : [ true, nil ]
      end

    end
  end
end