module Bitcoin
  module Ext
    module ObjectExt
      refine Object do
        def build_json
          if self.is_a?(Array)
            "[#{self.map{|o|o.to_h.to_json}.join(',')}]"
          else
            to_h.to_json
          end
        end

        def to_h
          return self if self.is_a?(String)
          instance_variables.inject({}) do |result, var|
            key = var.to_s
            key.slice!(0) if key.start_with?('@')
            value = instance_variable_get(var)
            if value.is_a?(Array)
              result.update(key => value.map{|v|v.to_h})
            else
              result.update(key => value.class.to_s.start_with?("Bitcoin::") ? value.to_h : value)
            end
          end
        end
      end
    end
  end
end
