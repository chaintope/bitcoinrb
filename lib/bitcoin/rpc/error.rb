module Bitcoin
  module RPC

    # An error answered by Bitcoin Core to an RPC request, or an answer which is not a JSON-RPC response.
    # It is a RuntimeError, as the error raised before it was, so an existing rescue still catches it.
    class Error < RuntimeError

      # @return [Integer, nil] The JSON-RPC error code answered by Bitcoin Core, such as -8 for an invalid
      # parameter, or nil if the error is not a JSON-RPC error.
      attr_reader :code
      # @return [Integer, nil] The HTTP status of the response.
      attr_reader :http_status
      # @return [Hash, nil] The error object of the JSON-RPC response as it was answered.
      attr_reader :data

      # @param [String] message The error message.
      # @param [Integer, nil] code The JSON-RPC error code.
      # @param [Integer, nil] http_status The HTTP status of the response.
      # @param [Hash, nil] data The error object of the JSON-RPC response.
      def initialize(message, code: nil, http_status: nil, data: nil)
        super(message)
        @code = code
        @http_status = http_status
        @data = data
      end

      # Build the error for the error object +error+ of a JSON-RPC response.
      # @param [Hash, Object] error The value of the error field of the response.
      # @param [Integer, nil] http_status The HTTP status of the response.
      # @return [Bitcoin::RPC::Error]
      def self.from_response(error, http_status: nil)
        if error.is_a?(Hash)
          code = error['code']
          code = Integer(code, exception: false) || code if code.is_a?(String)
          new(error['message'].to_s, code: code, http_status: http_status, data: error)
        else
          new(error.to_s, http_status: http_status, data: error)
        end
      end
    end

  end
end
