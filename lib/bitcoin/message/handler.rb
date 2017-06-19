module Bitcoin
  module Message

    # Default P2P message handler.
    class Handler

      attr_reader :logger
      attr_reader :conn

      def initialize(conn, logger = Bitcoin::Logger.create(:parser))
        @conn = conn
        @logger = logger
      end

      # handle p2p message.
      def handle(message)
        logger.info "handle message #{message.bth}"
        command, payload = parse_header(message)
        handle_command(command, payload)
      end

      private

      def parse_header(message)
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message header. message = #{message}" if message.nil? || message.size < HEADER_SIZE

        magic, command, length, checksum = message.unpack('a4A12Va4')
        unless magic.bth == head_magic
          logger.error("invalid header magic. #{magic.bth}")
          conn.close
        end

        payload = message[HEADER_SIZE...(HEADER_SIZE + length)]
        unless Bitcoin.double_sha256(payload)[0...4] == checksum
          logger.error("header checksum mismatch. #{checksum}")
          conn.close
        end
        [command, payload]
      end

      def handle_command(command, payload)
        case command
        when Version::COMMAND
          on_version(Version.parse_from_payload(payload))
        when VerAck::COMMAND
          on_ver_ack
        end
      end

      def on_version(version)
        logger.info("receive version message. #{version.to_json}")
        conn.send_data(VerAck.new.to_pkt)
      end

      def on_ver_ack
        logger.info('receive verack message.')
        conn.handshake_done
      end

    end
  end
end