use cosmos_sdk_proto::cosmos::{
    bank::v1beta1 as bank,
    base::v1beta1::{Coin, DecCoin},
    tx::v1beta1::BroadcastMode,
};
use hex_literal::hex;
use k256::ecdsa;
use txf::{OnlineParams, TxBuilder};

const GRPC_URL: &str = "http://127.0.0.1:9090";

// generated from seed phrase:
//
// crumble soon   hockey  pigeon  border   health
// human   cotton romance fork    mountain rapid
// scan    swarm  basic   subject tornado  genius
// parade  stone  coyote  pluck   journey  fatal
const PRIVKEY_BYTES: [u8; 32] = hex!("0ce1c769b1acd36d6676ee065fe9c9ceda84e542c0d41bcbeea78ee1f5246074");

#[tokio::main]
async fn main() -> Result<()> {
    let privkey = ecdsa::SigningKey::from_bytes(&PRIVKEY_BYTES.into())?;

    let res = TxBuilder::new()
        .add_message(bank::MsgSend {
            from_address: "cosmos1tqr9a9m9nk0c22uq2c2slundmqhtnrnhwks7x0".into(),
            to_address:   "cosmos1qskahqekuvwmyqgmusfdlg62eptczc4rd05mc2".into(),
            amount: vec![
                Coin {
                    denom:  "utoken".into(),
                    amount: "12345".into(),
                },
            ],
        })?
        .add_gas_price(DecCoin {
            denom:  "utoken".into(),
            amount: "0.0025".into(),
        })
        .sign_online(OnlineParams {
            privkey:        &privkey,
            grpc_url:       GRPC_URL.into(),
            bech_prefix:    "cosmos".into(),
            gas_adjustment: 1.4,
        })
        .await?
        .broadcast(GRPC_URL.into(), BroadcastMode::Sync)
        .await?
        .tx_response
        .ok_or(Error::TxResponseMissing)?;

    println!("Tx broadcasted!");
    dbg!(res);

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),

    #[error(transparent)]
    Txf(#[from] txf::Error),

    #[error("tx response missing")]
    TxResponseMissing,
}

type Result<T> = core::result::Result<T, Error>;
