#!/usr/bin/env ruby

require "rbnacl"

def bin_to_hex(bin)
  "0x#{bin.unpack1("H*")}"
end

def blake2b(data)
  RbNaCl::Hash::Blake2b.digest(data,
                               personal: "ckb-default-hash",
                               digest_size: 32)
end

if ARGV.length != 3
  STDERR.puts "Usage: runner.rb <script file> <secp data file> <witness args>"
  exit 1
end

script_binary = File.read(ARGV[0])
script_hash = blake2b(script_binary)
secp_data_binary = File.read(ARGV[1])

tx = DATA.read.sub("@FIB_CODE", bin_to_hex(script_binary))
  .sub("@SECP_DATA", bin_to_hex(secp_data_binary))
  .sub("@FIB_HASH", bin_to_hex(script_hash))
  .sub("@FIB_ARG", ARGV[2])

File.write("tx.json", tx)
# commandline = "/Users/ZhiChunLu/prototype/GPC/ckb-standalone-debugger/bins/target/release/ckb-debugger --tx-file tx.json --script-group-type type -i 0 -e input"
commandline = "../ckb-standalone-debugger/bins/target/release/ckb-debugger --tx-file tx.json --script-group-type type -i 0 -e input"
STDERR.puts "Executing: #{commandline}"
exec(commandline)

__END__
{
  "mock_info": {
    "inputs": [
      {
        "input": {
          "previous_output": {
            "tx_hash": "0xa98c57135830e1b91345948df6c4b8870828199a786b26f09f7dec4bc27a73da",
            "index": "0x0"
          },
          "since": "0x64"
        },
        "output": {
          "capacity": "0x4b9f96b00",
          "lock": {
            "args": "0x0064000000000000000000000000000000c6a8ae902ac272ea0ec6378f7ab8648f76979ce296a11bf182b0e952f6fcc685b43ae50e13951b78",
            "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "hash_type": "data"
          },
          "type": {
            "args": "0x",
            "code_hash": "@FIB_HASH",
            "hash_type": "data"
          }
        },
        "data": "0x"
      }
    ],
    "cell_deps": [
      {
        "cell_dep": {
          "out_point": {
            "tx_hash": "0xfcd1b3ddcca92b1e49783769e9bf606112b3f8cf36b96cac05bf44edcf5377e6",
            "index": "0x0"
          },
          "dep_type": "code"
        },
        "output": {
          "capacity": "0x702198d000",
          "lock": {
            "args": "0x",
            "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "hash_type": "data"
          },
          "type": null
        },
        "data": "@FIB_CODE"
      },
      {
        "cell_dep": {
          "out_point": {
            "tx_hash": "0xfcd1b3ddcca92b1e49783769e9bf606112b3f8cf36b96cac05bf44edcf5377e0",
            "index": "0x0"
          },
          "dep_type": "code"
        },
        "output": {
          "capacity": "0x702198d000",
          "lock": {
            "args": "0x",
            "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "hash_type": "data"
          },
          "type": null
        },
        "data": "@SECP_DATA"
      }
    ],
    "header_deps": []
  },
  "tx": {
    "version": "0x0",
    "cell_deps": [
      {
        "out_point": {
          "tx_hash": "0xfcd1b3ddcca92b1e49783769e9bf606112b3f8cf36b96cac05bf44edcf5377e6",
          "index": "0x0"
        },
        "dep_type": "code"
      },
      {
        "out_point": {
          "tx_hash": "0xfcd1b3ddcca92b1e49783769e9bf606112b3f8cf36b96cac05bf44edcf5377e0",
          "index": "0x0"
        },
        "dep_type": "code"
      }
    ],
    "header_deps": [
    ],
    "inputs": [
      {
        "previous_output": {
          "tx_hash": "0xa98c57135830e1b91345948df6c4b8870828199a786b26f09f7dec4bc27a73da",
          "index": "0x0"
        },
        "since": "0x64"
      }
    ],
    "outputs": [
      {
        "capacity": "0x0",
        "lock": {
          "args": "0x0164000000000000000000000000000000c6a8ae902ac272ea0ec6378f7ab8648f76979ce296a11bf182b0e952f6fcc685b43ae50e13951b78",
          "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "hash_type": "data"
        },
        "type": {
          "args": "0x",
          "code_hash": "0x3982bfaca9cd36a652f7133ae47e2f446d543bac449d20a9f1e7f7a6fd484dc0",
          "hash_type": "data"
        }
      }
    ],
    "witnesses": [
      "@FIB_ARG"
    ],
    "outputs_data": [
      "0x"
    ]
  }
}
