require 'spec_helper'

describe Bitcoin::ScriptInterpreter do

  describe 'run' do
    script_json = fixture_file('script_tests.json').select{ |j|j.size > 3}
    script_json = [
        ["", "DEPTH 0 EQUAL", "P2SH,STRICTENC", "OK", "Test the test: we should have an empty stack after scriptSig evaluation"],
        ["1 2", "2 EQUALVERIFY 1 EQUAL", "P2SH,STRICTENC", "OK", "Similarly whitespace around and between symbols"],
        ["0x01 0x0b", "11 EQUAL", "P2SH,STRICTENC", "OK", "push 1 byte"],
        ["0x02 0x417a", "'Az' EQUAL", "P2SH,STRICTENC", "OK"],
        ["0x4f 1000 ADD","999 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0", "IF 0x50 ENDIF 1", "P2SH,STRICTENC", "OK", "0x50 is reserved (ok if not executed)"],
        ["1","NOP", "P2SH,STRICTENC", "OK"],
        ["0", "IF VER ELSE 1 ENDIF", "P2SH,STRICTENC", "OK", "VER non-functional (ok if not executed)"],
        ["1", "DUP IF ENDIF", "P2SH,STRICTENC", "OK"],
        ["1 0", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "P2SH,STRICTENC", "OK"],
        ["1", "IF 1 ELSE 0 ELSE 1 ENDIF ADD 2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 0", "IF IF 1 ELSE 0 ENDIF ENDIF", "P2SH,STRICTENC", "OK"],
        ["'' 1", "IF SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ENDIF 0x14 0x68ca4fec736264c13b859bac43d5173df6871682 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0", "IF 1 IF RETURN ELSE RETURN ELSE RETURN ENDIF ELSE 1 IF 1 ELSE RETURN ELSE 1 ENDIF ELSE RETURN ENDIF ADD 2 EQUAL", "P2SH,STRICTENC", "OK", "Nested ELSE ELSE"],
        ["1 1", "VERIFY", "P2SH,STRICTENC", "OK"],
        ["10 0 11 TOALTSTACK DROP FROMALTSTACK", "ADD 21 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 IFDUP", "DEPTH 1 EQUALVERIFY 0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 IFDUP", "DEPTH 2 EQUALVERIFY 1 EQUALVERIFY 1 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 1", "NIP", "P2SH,STRICTENC", "OK"],
        ["1 0", "OVER DEPTH 3 EQUALVERIFY", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "0 PICK 20 EQUALVERIFY DEPTH 3 EQUAL", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "0 ROLL 20 EQUALVERIFY DEPTH 2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "ROT 22 EQUAL", "P2SH,STRICTENC", "OK"],
        ["25 24 23 22 21 20", "2ROT 24 EQUAL", "P2SH,STRICTENC", "OK"],
        ["25 24 23 22 21 20", "2ROT 2DROP 20 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 0", "SWAP 1 EQUALVERIFY 0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 1", "TUCK DEPTH 3 EQUALVERIFY SWAP 2DROP", "P2SH,STRICTENC", "OK"],
        ["13 14", "2DUP ROT EQUALVERIFY EQUAL", "P2SH,STRICTENC", "OK"],
        ["-1 0 1 2", "3DUP DEPTH 7 EQUALVERIFY ADD ADD 3 EQUALVERIFY 2DROP 0 EQUALVERIFY", "P2SH,STRICTENC", "OK"],
        ["1 2 3 5", "2OVER ADD ADD 8 EQUALVERIFY ADD ADD 6 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 3 5 7", "2SWAP ADD 4 EQUALVERIFY ADD 12 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 ABS", "0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 1 BOOLAND", "NOP", "P2SH,STRICTENC", "OK"],
        ["1 1ADD", "2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["111 1SUB", "110 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 1 BOOLOR", "NOP", "P2SH,STRICTENC", "OK"],
        ["11 10 1 ADD", "NUMEQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0 BOOLOR", "NOT", "P2SH,STRICTENC", "OK"],
        ["11 10 1 ADD", "NUMEQUALVERIFY 1", "P2SH,STRICTENC", "OK"],
        ["11 10", "LESSTHAN NOT", "P2SH,STRICTENC", "OK"],
        ["4 4", "GREATERTHAN NOT", "P2SH,STRICTENC", "OK"],
        ["11 10", "LESSTHANOREQUAL NOT", "P2SH,STRICTENC", "OK"],
        ["11 10", "GREATERTHANOREQUAL", "P2SH,STRICTENC", "OK"],
        ["1 0 MIN", "0 NUMEQUAL", "P2SH,STRICTENC", "OK"],
        ["2147483647 0 MAX", "2147483647 NUMEQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0 1", "WITHIN", "P2SH,STRICTENC", "OK"],
        ["0", "SIZE 0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1", "SIZE 1 EQUAL", "P2SH,STRICTENC", "OK"],
        ["127", "SIZE 1 EQUAL", "P2SH,STRICTENC", "OK"],
        ["128", "SIZE 2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0NOTEQUAL", "0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["2 -2 ADD", "0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["111 1 ADD 12 SUB", "100 EQUAL", "P2SH,STRICTENC", "OK"],
        ["-16 ABS", "-16 NEGATE EQUAL", "P2SH,STRICTENC", "OK"],
        ["-1 -1 ADD", "-2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["11 10 1 ADD", "NUMNOTEQUAL NOT", "P2SH,STRICTENC", "OK"],
        ["''", "RIPEMD160 0x14 0x9c1185a5c5e9fc54612808977ee8f548b2258d31 EQUAL", "P2SH,STRICTENC", "OK"],
        ["''", "SHA256 0x20 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 EQUAL", "P2SH,STRICTENC", "OK"],
        ["''", "DUP HASH160 SWAP SHA256 RIPEMD160 EQUAL", "P2SH,STRICTENC", "OK"],
        ["''", "DUP HASH256 SWAP SHA256 SHA256 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1","NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 1 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0 1", "EQUAL EQUAL", "P2SH,STRICTENC", "OK", "OP_0 and bools must have identical byte representations"],
        ["NOP", "CODESEPARATOR 1", "P2SH,STRICTENC", "OK"],
        ["NOP", "CHECKLOCKTIMEVERIFY 1", "P2SH,STRICTENC", "OK"],
        ["NOP", "CHECKSEQUENCEVERIFY 1", "P2SH,STRICTENC", "OK"],
        ["0", "0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 CHECKSIG NOT", "STRICTENC", "OK"],
        ["2 2 0 IF DIV ELSE 1 ENDIF", "NOP", "P2SH,STRICTENC", "DISABLED_OPCODE", "DIV disabled"],
        ["1", "RETURN 'data'", "P2SH,STRICTENC", "OP_RETURN", "canonical prunable txout format"],
        ["1", "NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 2 EQUAL", "P2SH,STRICTENC", "EVAL_FALSE"],
        ["1 0 1", "WITHIN NOT", "P2SH,STRICTENC", "OK"],
        ["0 1", "OVER DEPTH 3 EQUALVERIFY", "P2SH,STRICTENC", "EVAL_FALSE"],
        ["1", "IF 0xba ELSE 1 ENDIF", "P2SH,STRICTENC", "BAD_OPCODE", "opcodes above NOP10 invalid if executed"],
        ["NOP",
         "0 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' 0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f 2DUP 0x616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
         "P2SH,STRICTENC",
         "SCRIPT_SIZE",
         "10,001-byte scriptPubKey"],
        ["", "0 0 0 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", "P2SH,STRICTENC", "OK", "CHECKMULTISIG is allowed to have zero keys and/or sigs"],
        ["549755813888", "0x06 0xFFFFFFFF7F EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0", "1 0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 1 CHECKMULTISIG NOT", "STRICTENC", "OK"],
        [
            "0 0x47 0x3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501 0x47 0x3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501",
            "2 0 0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 2 CHECKMULTISIG NOT",
            "STRICTENC", "OK",
            "2-of-2 CHECKMULTISIG NOT with the second pubkey invalid, and both signatures validly encoded. Valid pubkey fails, and CHECKMULTISIG exits early, prior to evaluation of second invalid pubkey."
        ],
        ["0x25 0x30220220000000000000000000000000000000000000000000000000000000000000000000", "0 CHECKSIG NOT", "", "OK", "Missing S is correctly encoded"],
        ["2147483648 0 ADD", "NOP", "P2SH,STRICTENC", "UNKNOWN_ERROR", "arithmetic operands must be in range [-2^31...2^31] "],
        ["1",
         "0x61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
         "P2SH,STRICTENC",
         "OP_COUNT",
         ">201 opcodes executed. 0x61 is NOP"],
        ["0x09 0x00000000 0x00000000 0x10", "", "P2SH,STRICTENC", "OK", "equals zero when cast to Int64"],
        ["0x4c 0x00", "DROP 1", "MINIMALDATA", "MINIMALDATA", "Empty vector minimally represented by OP_0"],
        ["0x01 0x00", "NOT DROP 1", "MINIMALDATA", "UNKNOWN_ERROR", "numequals 0"],
        ["0 0x01 1", "HASH160 0x14 0xda1745e9b549bd0bfa1a569971c77eba30cd5a4b EQUAL", "P2SH,STRICTENC", "OK", "Very basic P2SH"],
        [
            "0x47 0x304402204e2eb034be7b089534ac9e798cf6a2c79f38bcb34d1b179efd6f2de0841735db022071461beb056b5a7be1819da6a3e3ce3662831ecc298419ca101eb6887b5dd6a401 0x19 0x76a9147cf9c846cd4882efec4bf07e44ebdad495c94f4b88ac",
            "HASH160 0x14 0x2df519943d5acc0ef5222091f9dfe3543f489a82 EQUAL",
            "P2SH",
            "EQUALVERIFY",
            "P2SH(P2PKH), bad sig"
        ],
        ["1 TOALTSTACK", "FROMALTSTACK 1", "P2SH,STRICTENC", "INVALID_ALTSTACK_OPERATION", "alt stack not shared between sig/pubkey"],
        ["0 IF 0x4c 0x00 ENDIF 1", "", "MINIMALDATA", "OK", "non-minimal PUSHDATA1 ignored"],
        ["0x4e 0x01000000 0x09","9 EQUAL", "P2SH,STRICTENC", "OK", "0x4e is OP_PUSHDATA4"],
        ["0x4c 0x01 0x07","7 EQUAL", "P2SH,STRICTENC", "OK", "0x4c is OP_PUSHDATA1"],
        ["0x4c 0 0x01 1", "HASH160 0x14 0xda1745e9b549bd0bfa1a569971c77eba30cd5a4b EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 IF 0x4c 0x00000000 ENDIF 1", "", "MINIMALDATA", "OK", "non-minimal PUSHDATA4 ignored"],
        ["0x4c01","0x01 NOP", "P2SH,STRICTENC","BAD_OPCODE", "PUSHDATA1 with not enough bytes"],
        ["NOP",
         "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
         "P2SH,STRICTENC",
         "PUSH_SIZE",
         ">520 byte push"],
        ["0",
         "IF 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' ENDIF 1",
         "P2SH,STRICTENC",
         "PUSH_SIZE",
         ">520 byte push in non-executed IF branch"],
        ["1 2 3 4 5 0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
         "1 2 3 4 5 6 0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
         "P2SH,STRICTENC",
         "STACK_SIZE",
         ">1,000 stack size (0x6f is 3DUP)"],
        ["2147483647", "1ADD 1SUB 1", "P2SH,STRICTENC", "UNKNOWN_ERROR", "We cannot do math on 5-byte integers, even if the result is 4-bytes"],
        [["00", 0.00000000 ], "", "0 0x206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "P2SH,WITNESS", "EVAL_FALSE", "Invalid witness script"],
        [
          "0x47 0x304402200a5c6163f07b8d3b013c4d1d6dba25e780b39658d79ba37af7057a3b7f15ffa102201fd9b4eaa9943f734928b99a83592c2e7bf342ea2680f6a2bb705167966b742001",
          "0x41 0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG",
          "",
          "OK",
          "P2PK"
        ],
        [
            "0x48 0x304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401",
            "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            "DERSIG",
            "SIG_DER",
            "P2PK with too much S padding"
        ],
        [
            "0x47 0x30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
            "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            "",
            "OK",
            "P2PK with too little R padding but no DERSIG"
        ],
        [
            "0x09 0x300602010102010101",
            "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            "DERSIG,NULLFAIL",
            "NULLFAIL",
            "BIP66 example 4, with DERSIG and NULLFAIL, non-null DER-compliant signature"
        ],
        [
            "0x48 0x304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef001",
            "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG",
            "LOW_S",
            "SIG_HIGH_S",
            "P2PK with high S"
        ],
        [
          "",
          "0 0x20 0xb95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64",
          "P2SH,WITNESS",
          "WITNESS_PROGRAM_WITNESS_EMPTY",
          "P2WSH with empty witness"
        ],
        [
            "0x47 0x30440220035d554e3153c14950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            "0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG NOT",
            "",
            "EVAL_FALSE",
            "P2PK NOT with hybrid pubkey but no STRICTENC"
        ],
        ["11 0x47 0x304402200a5c6163f07b8d3b013c4d1d6dba25e780b39658d79ba37af7057a3b7f15ffa102201fd9b4eaa9943f734928b99a83592c2e7bf342ea2680f6a2bb705167966b742001", "0x41 0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG", "CLEANSTACK,P2SH", "CLEANSTACK", "P2PK with unnecessary input"],
        ["0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x09 0x300602010102010101", "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT", "DERSIG,NULLFAIL", "NULLFAIL", "BIP66-compliant but not NULLFAIL-compliant"],
        [
            [
                "304402201e7216e5ccb3b61d46946ec6cc7e8c4e0117d13ac2fd4b152197e4805191c74202203e9903e33e84d9ee1dd13fb057afb7ccfb47006c23f6a067185efbc9dd780fc501",
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                0.00000001
            ],
            "",
            "0 0x14 0x91b24bf9f5288532960ac687abb035127b1d28a5",
            "P2SH,WITNESS",
            "OK",
            "Basic P2WPKH"
        ],
        [
            [
                "30440220069ea3581afaf8187f63feee1fd2bd1f9c0dc71ea7d6e8a8b07ee2ebcf824bf402201a4fdef4c532eae59223be1eda6a397fc835142d4ddc6c74f4aa85b766a5c16f01",
                "41048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26cafac",
                0.00000000
            ],
            "0x22 0x0020ac8ebd9e52c17619a381fa4f71aebb696087c6ef17c960fd0587addad99c0610",
            "HASH160 0x14 0x61039a003883787c0d6ebc66d97fdabe8e31449d EQUAL",
            "P2SH,WITNESS",
            "EVAL_FALSE",
            "Basic P2SH(P2WSH) with the wrong key"
        ],
        [
            [
                "304402200d461c140cfdfcf36b94961db57ae8c18d1cb80e9d95a9e47ac22470c1bf125502201c8dc1cbfef6a3ef90acbbb992ca22fe9466ee6f9d4898eda277a7ac3ab4b25101",
                "410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
                0.00000001
            ],
            "",
            "0 0x20 0xb95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64",
            "P2SH,WITNESS",
            "OK",
            "Basic P2WSH"
        ],
        [
            [
                "304402205ae57ae0534c05ca9981c8a6cdf353b505eaacb7375f96681a2d1a4ba6f02f84022056248e68643b7d8ce7c7d128c9f1f348bcab8be15d094ad5cadd24251a28df8001",
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                0.00000000
            ],
            "",
            "1 0x14 0x91b24bf9f5288532960ac687abb035127b1d28a5",
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,P2SH,WITNESS",
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            "P2WPKH with future witness version"
        ],
        [
            [
                "",
                "304402202d092ededd1f060609dbf8cb76950634ff42b3e62cf4adb69ab92397b07d742302204ff886f8d0817491a96d1daccdcc820f6feb122ee6230143303100db37dfa79f01",
                "5121038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b852ae",
                0.00000001
            ],
            "",
            "0 0x20 0x08a6665ebfd43b02323423e764e185d98d1587f903b81507dbb69bfc41005efa",
            "P2SH,WITNESS",
            "OK",
            "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key"
        ],
        ["-1", "CHECKSEQUENCEVERIFY", "CHECKSEQUENCEVERIFY", "NEGATIVE_LOCKTIME", "CSV automatically fails if stack top is negative"],
        [["00", "645168", 1.0e-08], "0x22 0x0020f913eacf2e38a5d6fc3a8311d72ae704cb83866350a984dd3e5eb76d2a8c28e8", "HASH160 0x14 0xdbb7d1c0a56b7a9c423300c8cca6e6e065baf1dc EQUAL", "P2SH,WITNESS,MINIMALIF", "MINIMALIF"]

    ]
    script_json.each do| r |
      it "should validate script #{r.inspect}" do
        puts r.inspect
        if r[0].is_a?(Array)
          witness = Bitcoin::ScriptWitness.new(r[0][0..-2].map{ |v| v.htb })
          sig, pubkey, flags, error_code = r[1], r[2], r[3], r[4]
          amount = (r[0][-1] * 100_000_000).to_i
        else
          witness, sig, pubkey, flags, error_code = Bitcoin::ScriptWitness.new, r[0], r[1], r[2], r[3]
          amount = 0
        end
        script_sig = Bitcoin::TestScriptParser.parse_script(sig)
        script_pubkey = Bitcoin::TestScriptParser.parse_script(pubkey)
        credit_tx = build_credit_tx(script_pubkey, amount)
        tx = build_spending_tx(script_sig, credit_tx, witness, amount)
        puts "script_pubkey = #{script_pubkey.to_payload.bth}"
        puts ""
        puts "tx = #{tx.to_payload.bth}"
        flags = flags.split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}
        expected_err_code = find_error_code(error_code)
        i = Bitcoin::ScriptInterpreter.new(flags: flags, checker: Bitcoin::TxChecker.new(tx: tx, input_index: 0, amount: amount))
        result = i.verify(script_sig, script_pubkey, witness)
        puts i.error.to_s
        expect(result).to be expected_err_code == Bitcoin::ScriptError::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result
      end
    end
  end

  def build_dummy_tx(script_sig, txid)
    tx = Bitcoin::Tx.new
    tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.new(txid, 0), script_sig: script_sig)
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new)
    tx
  end

  def build_credit_tx(script_pubkey, amount)
    tx = Bitcoin::Tx.new
    tx.version = 1
    tx.lock_time = 0
    coinbase = Bitcoin::Script.new << 0 << 0
    tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.create_coinbase_outpoint, script_sig: coinbase)
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: script_pubkey, value: amount)
    tx
  end

  def build_spending_tx(script_sig, locked_tx, witness, amount)
    tx = Bitcoin::Tx.new
    tx.version = 1
    tx.lock_time = 0
    tx.inputs << Bitcoin::TxIn.new(
      out_point: Bitcoin::OutPoint.new(locked_tx.txid, 0),
      script_sig: script_sig,
      script_witness: witness
    )
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new, value: amount)
    tx
  end

  def find_error_code(error_code)
    error_code = 'SIG_NULLFAIL' if error_code == 'NULLFAIL'
    Bitcoin::ScriptError.name_to_code('SCRIPT_ERR_' + error_code)
  end

end