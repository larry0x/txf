use bech32::{ToBase32, Variant};
use cosmos_sdk_proto::{
    cosmos::{
        auth::v1beta1::{self as auth, BaseAccount},
        base::{
            tendermint::v1beta1 as tm,
            v1beta1::{Coin, DecCoin},
        },
        crypto::secp256k1,
        tx::{
            signing::v1beta1::SignMode,
            v1beta1::{
                self as tx, mode_info, AuthInfo, BroadcastTxResponse, Fee, ModeInfo, SignDoc,
                SignerInfo, Tx, TxBody, BroadcastMode,
            },
        },
    },
    prost::{DecodeError, EncodeError},
    traits::{MessageExt, TypeUrl},
    Any,
};
use k256::{
    ecdsa::{self, signature::Signer, VerifyingKey},
    sha2::{Digest, Sha256},
};
use ripemd::Ripemd160;

pub struct OnlineParams<'a> {
    pub privkey:        &'a ecdsa::SigningKey,
    pub grpc_url:       String,
    pub bech_prefix:    String,
    pub gas_adjustment: f64,
}

pub struct OfflineParams<'a> {
    pub privkey:        &'a ecdsa::SigningKey,
    pub chain_id:       String,
    pub account_number: u64,
    pub sequence:       u64,
    pub gas_limit:      u64,
}

#[derive(Clone)]
struct Credential {
    auth_info: AuthInfo,
    signature: Vec<u8>,
}

#[derive(Default)]
pub struct TxBuilder {
    gas_price:  Option<DecCoin>,
    msgs:       Vec<Any>,
    credential: Option<Credential>,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_message<M>(mut self, msg: M) -> Result<Self>
    where
        M: MessageExt + TypeUrl + 'static,
    {
        self.msgs.push(msg.to_any()?);
        Ok(self)
    }

    pub fn add_messages<M>(mut self, msgs: Vec<M>) -> Result<Self>
    where
        M: MessageExt + TypeUrl + 'static,
    {
        for msg in msgs.iter() {
            self.msgs.push(msg.to_any()?);
        }

        Ok(self)
    }

    pub fn set_gas_price(mut self, gas_price: DecCoin) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub async fn sign_online(self, params: OnlineParams<'_>) -> Result<Self> {
        let chain_id = query_chain_id(params.grpc_url.clone()).await?;

        let pubkey_bytes = derive_pubkey(params.privkey);
        let address = derive_address(&pubkey_bytes, &params.bech_prefix)?;
        let account = query_account(params.grpc_url.clone(), address).await?;

        let gas_used = simulate_gas(params.grpc_url.clone(), self.body(), &account).await?;
        let gas_limit = (gas_used as f64 * params.gas_adjustment).floor() as u64;

        let auth_info = AuthInfo {
            signer_infos: vec![
                SignerInfo {
                    public_key: account.pub_key.clone(),
                    mode_info:  Some(mode_info(SignMode::Direct)),
                    sequence:   account.sequence,
                },
            ],
            fee: Some(fee(gas_limit, &self.gas_price)?),
            tip: None,
        };

        self.sign(params.privkey, auth_info, chain_id, account.account_number)
    }

    pub fn sign_offline(self, params: OfflineParams) -> Result<Self> {
        let pubkey = secp256k1::PubKey { key: derive_pubkey(params.privkey) };

        let auth_info = AuthInfo {
            signer_infos: vec![
                SignerInfo {
                    public_key: Some(pubkey.to_any()?),
                    mode_info:  Some(mode_info(SignMode::Direct)),
                    sequence:   params.sequence,
                },
            ],
            fee: Some(fee(params.gas_limit, &self.gas_price)?),
            tip: None,
        };

        self.sign(params.privkey, auth_info, params.chain_id, params.account_number)
    }

    fn sign(
        mut self,
        privkey: &ecdsa::SigningKey,
        auth_info: AuthInfo,
        chain_id: String,
        account_number: u64,
    ) -> Result<Self> {
        let sign_doc = SignDoc {
            body_bytes:      self.body().to_bytes()?,
            auth_info_bytes: auth_info.to_bytes()?,
            chain_id,
            account_number,
        };

        let sign_doc_bytes = sign_doc.to_bytes()?;
        let signature: ecdsa::Signature = privkey.sign(&sign_doc_bytes);

        self.credential = Some(Credential {
            auth_info,
            signature: signature.to_bytes().to_vec(),
        });

        Ok(self)
    }

    fn body(&self) -> TxBody {
        TxBody {
            messages:                       self.msgs.clone(),
            memo:                           "".into(),
            timeout_height:                 0,
            extension_options:              vec![],
            non_critical_extension_options: vec![],
        }
    }

    fn tx(&self) -> Result<Tx> {
        let cred = self.credential.clone().ok_or(Error::Unsigned)?;

        Ok(Tx {
            body:       Some(self.body()),
            auth_info:  Some(cred.auth_info),
            signatures: vec![cred.signature],
        })
    }

    pub async fn broadcast(self, grpc_url: String, mode: BroadcastMode) -> Result<BroadcastTxResponse> {
        tx::service_client::ServiceClient::connect(grpc_url)
            .await?
            .broadcast_tx(tx::BroadcastTxRequest {
                tx_bytes: self.tx()?.to_bytes()?,
                mode:     mode.into(),
            })
            .await
            .map(|res| res.into_inner())
            .map_err(Into::into)
    }
}

async fn simulate_gas(grpc_url: String, body: TxBody, account: &BaseAccount) -> Result<u64> {
    let sim_tx = Tx {
        body:      Some(body),
        auth_info: Some(AuthInfo {
            signer_infos: vec![
                SignerInfo {
                    public_key: account.pub_key.clone(),
                    mode_info:  Some(mode_info(SignMode::Unspecified)),
                    sequence:   account.sequence,
                },
            ],
            fee: Some(Fee {
                amount:    vec![],
                gas_limit: 0,
                payer:     "".into(),
                granter:   "".into(),
            }),
            tip: None,
        }),
        signatures: vec![vec![]],
    };

    tx::service_client::ServiceClient::connect(grpc_url)
        .await?
        .simulate(
            // yeah i know it's deprecated thank you
            #[allow(deprecated)]
            tx::SimulateRequest {
                tx: None,
                tx_bytes: sim_tx.to_bytes()?,
            },
        )
        .await?
        .into_inner()
        .gas_info
        .ok_or(Error::GasInfoMissing)
        .map(|gas_info| gas_info.gas_used)
}

async fn query_chain_id(grpc_url: String) -> Result<String> {
    tm::service_client::ServiceClient::connect(grpc_url)
        .await?
        .get_node_info(tm::GetNodeInfoRequest {})
        .await?
        .into_inner()
        .default_node_info
        .ok_or(Error::NodeInfoMissing)
        .map(|node_info| node_info.network)
}

async fn query_account(grpc_url: String, address: String) -> Result<BaseAccount> {
    let any = auth::query_client::QueryClient::connect(grpc_url)
        .await?
        .account(auth::QueryAccountRequest {
            address: address.clone(),
        })
        .await?
        .into_inner()
        .account
        .ok_or(Error::AccountNotFound {
            address,
        })?;

    BaseAccount::from_any(&any).map_err(Into::into)
}

fn fee(gas_limit: u64, gas_price: &Option<DecCoin>) -> Result<Fee> {
    let amount = match gas_price {
        Some(gas_price) => {
            let gas_price_dec: f64 = gas_price.amount.parse()?;

            let coin = Coin {
                denom:  gas_price.denom.clone(),
                amount: (gas_limit as f64 * gas_price_dec).floor().to_string(),
            };

            vec![coin]
        },
        None => vec![],
    };

    Ok(Fee {
        amount,
        gas_limit,
        payer:   "".into(),
        granter: "".into(),
    })
}

fn mode_info(mode: SignMode) -> ModeInfo {
    ModeInfo {
        sum: Some(mode_info::Sum::Single(mode_info::Single {
            mode: mode.into(),
        })),
    }
}

fn derive_pubkey(privkey: &ecdsa::SigningKey) -> Vec<u8> {
    VerifyingKey::from(privkey)
        .to_encoded_point(true)
        .to_bytes()
        .to_vec()
}

fn derive_address(pubkey_bytes: &[u8], bech_prefix: &str) -> Result<String> {
    let addr_bytes = ripemd160(&sha256(pubkey_bytes));

    bech32::encode(bech_prefix, addr_bytes.to_base32(), Variant::Bech32).map_err(Into::into)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn ripemd160(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Bech32(#[from] bech32::Error),

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error(transparent)]
    Encode(#[from] EncodeError),

    #[error(transparent)]
    ParseFloat(#[from] std::num::ParseFloatError),

    #[error(transparent)]
    Status(#[from] tonic::Status),

    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),

    #[error("account not found for address `{address}`")]
    AccountNotFound { address: String },

    #[error("gas price is not set")]
    GasPriceUnset,

    #[error("gas info missing in SimulationResponse")]
    GasInfoMissing,

    #[error("node info missing in GetNodeInfoResponse")]
    NodeInfoMissing,

    #[error("tx has not been signed yet")]
    Unsigned,
}

type Result<T> = core::result::Result<T, Error>;

// ----------------------------------- Tests -----------------------------------

#[cfg(test)]
mod tests {
    use cosmos_sdk_proto::cosmos::bank::v1beta1 as bank;
    use hex_literal::hex;

    use super::*;

    // generated from seed phrase:
    //
    // crumble soon   hockey  pigeon  border   health
    // human   cotton romance fork    mountain rapid
    // scan    swarm  basic   subject tornado  genius
    // parade  stone  coyote  pluck   journey  fatal
    const PUBKEY_BYTES:  [u8; 33] = hex!("02dfd9e2e543bdc33063faa0c5d9322eb58587a9a7ec03d3fa7a61d728e2d92fca");
    const PRIVKEY_BYTES: [u8; 32] = hex!("0ce1c769b1acd36d6676ee065fe9c9ceda84e542c0d41bcbeea78ee1f5246074");
    const ADDRESS:       &str     = "cosmos1tqr9a9m9nk0c22uq2c2slundmqhtnrnhwks7x0";
    const BECH_PREFIX:   &str     = "cosmos";

    fn mock_privkey() -> ecdsa::SigningKey {
        ecdsa::SigningKey::from_bytes(&PRIVKEY_BYTES.into()).unwrap()
    }

    #[test]
    fn processing_key() {
        let privkey = mock_privkey();

        let pubkey_bytes = derive_pubkey(&privkey);
        assert_eq!(pubkey_bytes, PUBKEY_BYTES);

        let address = derive_address(&pubkey_bytes, BECH_PREFIX).unwrap();
        assert_eq!(address, ADDRESS);
    }

    #[test]
    fn signing_offline() {
        // the correct signature, generated by:
        //
        // simd tx bank send $from $to 123456utoken --generate-only --output document tx.json
        // simd tx sign tx.json --from $from --offline --chain-id dev-1 --sequence 13 --account-number 0
        const SIG_BYTES: &str = "sTPWXiJYpNYE01j6Hp/YuSRu/WfoRvCXl9XB0/Us4RZm8K0GLAjCp5S+mTmEq1woyi3hstCvyljv254HIt/t3g==";

        let privkey = mock_privkey();

        let credential = TxBuilder::new()
            .add_message(bank::MsgSend {
                from_address: ADDRESS.into(),
                to_address:   "cosmos1qskahqekuvwmyqgmusfdlg62eptczc4rd05mc2".into(),
                amount: vec![
                    Coin {
                        denom:  "utoken".into(),
                        amount: "12345".into(),
                    },
                ],
            })
            .unwrap()
            .set_gas_price(DecCoin {
                denom:  "utoken".into(),
                amount: "0.0025".into(),
            })
            .sign_offline(OfflineParams {
                privkey:        &privkey,
                chain_id:       "dev-1".into(),
                account_number: 0,
                sequence:       13,
                gas_limit:      123456,
            })
            .unwrap()
            .credential
            .unwrap();

        assert_eq!(base64::encode(credential.signature), SIG_BYTES);
    }
}
