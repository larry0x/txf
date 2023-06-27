# txf

Transaction factory - a library facilitating the signing and broadcasting of transactions (txs) on [Cosmos SDK](https://github.com/cosmos/cosmos-sdk)-based blockchains.

## Features

- support two signing modes:
  - online: the builder will query user account info onchain and simulate gas usage
  - offline: the user must provide account info and gas limit
- support two broadcasting modes:
  - async: exit immediately once the tx has been sent out, do not wait for confirmation
  - sync: wait for tx confirmation (may take a few blocks of time)
- only support single signature (no multisig)
- only support the DIRECT sign mode

## How to use

Example with ONLINE signing mode and SYNC broadcast mode:

```rust
use cosmos_sdk_proto::cosmos::{bank, staking};
use txf::{OnlineParams, TxBuilder};

let res = TxBuilder::new()
    .add_message(bank::v1beta1::MsgSend {
        from_address: "osmo1...",
        to_address:   "osmo1...",
        amount: vec![
            Coin {
                denom:  "...",
                amount: "...",
            },
        ],
    })?
    .add_message(staking::v1beta1::MsgDelegate {
        delegator_address: "cosmos1...",
        validator_address: "cosmos1...",
        amount: Coin {
            denom:  "...",
            amount: "...",
        },
    })?
    .sign_online(OnlineParams {
        privkey:        &privkey,
        grpc_url:       grpc_url.clone(),
        bech_prefix:    "cosmos".into(),
        gas_adjustment: 1.4,
    })
    .await?
    .broadcast_sync(grpc_url)
    .await?;
```

## Copyright

(c) larry0x, 2023 - [All rights reserved](./License).
