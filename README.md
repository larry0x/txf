# txf

Transaction factory - a library facilitating the signing and broadcasting of transactions (txs) on [Cosmos SDK](https://github.com/cosmos/cosmos-sdk)-based blockchains.

## How to use

Example with ONLINE signing mode and SYNC broadcast mode:

```rust
use cosmos_sdk_proto::cosmos::{
    bank,
    base::v1beta1::{Coin, DecCoin},
    staking,
    tx::v1beta1::BroadcastMode,
};
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
    .set_gas_price(DecCoin {
        denom:  "uosmo".into()
        amount: "0.0025".into(),
    })
    .sign_online(OnlineParams {
        privkey:        &privkey,
        grpc_url:       grpc_url.clone(),
        bech_prefix:    "cosmos".into(),
        gas_adjustment: 1.4,
    })
    .await?
    .broadcast(grpc_url, BroadcastMode::Sync)
    .await?;
```

## License

Either [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/license/mit/) license, at your choice.
