require 'spec_helper'

RSpec.describe 'BIP-0371' do

  describe 'Test Vector' do
    context 'invalid' do
      it 'raise error' do
        # Case: PSBT With PSBT_IN_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)
        base64 = 'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARchAv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyAAAA'
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid x-only public key size for the type tap internal key')
        # Case: PSBT With PSBT_KEY_PATH_SIG signature that is too short
        base64 = 'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARM/Fzuz02wHSvtxb+xjB6BpouRQuZXzyCeFlFq43w4kJg3NcDsMvzTeOZGEqUgawrNYbbZgHwJqd/fkk4SBvDR1AAAA'
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid schnorr signature size for the type tap key sig')
        # Case: PSBT With PSBT_KEY_PATH_SIG signature that is too long
        base64 = 'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARNCFzuz02wHSvtxb+xjB6BpouRQuZXzyCeFlFq43w4kJg3NcDsMvzTeOZGEqUgawrNYbbZgHwJqd/fkk4SBvDR1FwGqAAAA'
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid schnorr signature size for the type tap key sig')
        # Case: PSBT With PSBT_IN_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)
        base64 = 'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXIhYC/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIZAHcrLadWAACAAQAAgAAAAIABAAAAAAAAAAAAAA=='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Size of key was not the expected size for the type tap bip32 derivation')
        # Case: PSBT With PSBT_OUT_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)
        base64 = 'cHNidP8BAH0CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Aoh7AQAAAAAAFgAUI4KHHH6EIaAAk/dU2RKB5nWHS59gawQqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAABBSEC/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIA'
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid x-only public key size for the type tap internal key')
        # Case: PSBT With PSBT_OUT_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)
        base64 = 'cHNidP8BAH0CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Aoh7AQAAAAAAFgAUI4KHHH6EIaAAk/dU2RKB5nWHS59gawQqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAiBwL+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAAA=='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Size of key was not the expected size for the type tap bip32 derivation')
        # Case: PSBT With PSBT_IN_TAP_SCRIPT_SIG key that is too long (incorrectly serialized as compressed DER)
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJCFAIssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20s2XDhX1P8DIL5UP1WD/qRm3YXK+AXNoqJkTrwdPQAsJQIl1aqNznMxonsD886NgvjLMC1mxbpOh6LtGBXJrLKej/3BsQXZkljKyzGjh+RK4pXjjcZzncQiFx6lm9JvNQ8sAAA=='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Size of key was not the expected size for the type tap script sig')
        # Case: PSBT With PSBT_IN_TAP_SCRIPT_SIG signature that is too long
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwlCiXVqo3OczGiewPzzo2C+MswLWbFuk6Hou0YFcmssp6P/cGxBdmSWMrLMaOH5ErileONxnOdxCIXHqWb0m81DywEBAAA='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid schnorr signature size for the type tap script sig')
        # Case: PSBT With PSBT_IN_TAP_SCRIPT_SIG signature that is too short
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwk/iXVqo3OczGiewPzzo2C+MswLWbFuk6Hou0YFcmssp6P/cGxBdmSWMrLMaOH5ErileONxnOdxCIXHqWb0m81DAAA='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid schnorr signature size for the type tap script sig')
        # Case: PSBT With PSBT_IN_TAP_LEAF_SCRIPT Control block that is too long
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJjFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgAIyAssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20qzAAAA='
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid data length for path in Control Block')
        # Case: PSBT With PSBT_IN_TAP_LEAF_SCRIPT Control block that is too short
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJhFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4SMgLLE6xoJI3oBqpqNlnPPAPraCHQnIEUpOho/r3oZbttKswAAA'
        expect{Bitcoin::PSBT::Tx.parse_from_base64(base64)}.to raise_error(ArgumentError, 'Invalid data length for path in Control Block')
      end
    end

    context 'valid' do
      it 'parse correctly' do
        # Case: PSBT with one P2TR key only input with internal key and its derivation path
        base64 = 'cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgAiAgNrdyptt02HU8mKgnlY3mx4qzMSEJ830+AwRIQkLs5z2Bh3Ky2nVAAAgAEAAIAAAACAAAAAAAAAAAAA'
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.to_base64).to eq(base64)
        # Case: PSBT with one P2TR key only input with internal key, its derivation path, and signature
        base64 = 'cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1cBE0C7U+yRe62dkGrxuocYHEi4as5aritTYFpyXKdGJWMUdvxvW67a9PLuD0d/NvWPOXDVuCc7fkl7l68uPxJcl680IRb+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAARcg/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIAIgIDa3cqbbdNh1PJioJ5WN5seKszEhCfN9PgMESEJC7Oc9gYdystp1QAAIABAACAAAAAgAAAAAAAAAAAAA=='
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.to_base64).to eq(base64)
        # Case: PSBT with one P2TR key only output with internal key and its derivation path
        base64 = 'cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSARJNp67JLM0GyVRWJkf0N7E4uVchqEvivyJ2u92rPmcSEHESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEZAHcrLadWAACAAQAAgAAAAIAAAAAABQAAAAA='
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.to_base64).to eq(base64)
        # Case: PSBT with one P2TR script path only input with dummy internal key, scripts, derivation paths for keys in the scripts, and merkle root
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA'
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.inputs[0].tap_leaf_scripts.size).to eq(3)
        expect(psbt.inputs[0].tap_bip32_derivations.size).to eq(4)
        expect(psbt.to_base64).to eq(base64)
        # Case: PSBT with one P2TR script path only output with dummy internal key, taproot tree, and script key derivation paths
        base64 = 'cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgCoy9yG3hzhwPnK6yLW33ztNoP+Qj4F0eQCqHk0HW9vUAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAEGbwLAIiBzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAqwCwCIgYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWmsAcAiIET6pJoDON5IjI3//s37bzKfOAvVZu8gyN9tgT6rHEJzrCEHRPqkmgM43kiMjf/+zftvMp84C9Vm7yDI322BPqscQnM5AfBreYuSoQ7ZqdC7/Trxc6U7FhfaOkFZygCCFs2Fay4Odystp1YAAIABAACAAQAAgAAAAAADAAAAIQdQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAUAfEYeXSEHYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWk5ARis5AmIl4Xg6nDO67jhyokqenjq7eDy4pbPQ1lhqPTKdystp1YAAIABAACAAgAAgAAAAAADAAAAIQdzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAjkBKaW0kVCQFi11mv0/4Pk/ozJgVtC0CIy5M8rngmy42Cx3Ky2nVgAAgAEAAIADAACAAAAAAAMAAAAA'
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.outputs.length).to eq(1)
        expect(psbt.outputs[0].tap_internal_key).to eq('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
        expect(psbt.to_base64).to eq(base64)
        # Case: PSBT with one P2TR script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures
        base64 = 'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwlAv4GNl1fW/+tTi6BX+0wfxOD17xhudlvrVkeR4Cr1/T1eJVHU404z2G8na4LJnHmu0/A5Wgge/NLMLGXdfmk9eUEUQyCwvxbwEbU+p75hWSSqfyfl0prSDqEVXYSGdsO60bIRXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+EDh8atvq/omsjbyGDNxncHUKKt2jYD5H5mI2KvvR7+4Y7sfKlKfdowV8AzjTsKDzcB+iPhCi+KPbvZAQ8MpEYEaQRT6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqW99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwQOwfA3kgZGHIM0IoVCMyZwirAx8NpKJT7kWq+luMkgNNi2BUkPjNE+APmJmJuX4hX6o28S3uNpPS2szzeBwXV/ZiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA'
        psbt = Bitcoin::PSBT::Tx.parse_from_base64(base64)
        expect(psbt.to_base64).to eq(base64)
      end
    end
  end

end