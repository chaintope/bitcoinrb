module OpenAssets

  module MarkerOutput

    # whether this output is marker output for open assets.
    def open_assets_marker?
      return false unless script_pubkey.op_return?
      !oa_payload.nil?
    end

    # get open asset payload.
    # @return [OpenAssets::Payload] open asset payload.
    def oa_payload
      return nil unless script_pubkey.op_return?
      Payload.parse_from_payload(script_pubkey.op_return_data)
    end

  end

end
