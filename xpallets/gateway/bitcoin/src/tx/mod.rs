// Copyright 2019-2021 ChainX Project Authors. Licensed under GPL-3.0.
#![allow(clippy::ptr_arg)]
extern crate alloc;

use alloc::string::ToString;

pub mod validator;

use frame_support::{
    dispatch::DispatchResult,
    log::{self, debug, error, info, warn},
    traits::{tokens::fungibles::Mutate, Get},
};
use sp_runtime::{traits::Zero, SaturatedConversion};
use sp_std::prelude::*;

use light_bitcoin::{
    chain::Transaction,
    keys::{Address, Network},
    primitives::{hash_rev, H256},
};
use xp_assets_registrar::Chain;

pub use self::validator::validate_transaction;
use crate::{
    types::{AccountInfo, BtcAddress, BtcDepositCache, BtcTxResult, BtcTxState},
    Config, Event, Pallet, PendingDeposits, WithdrawalProposal,
};
use xp_gateway_bitcoin::{BtcDepositInfo, BtcTxMetaType, BtcTxTypeDetector};
use xp_gateway_common::AccountExtractor;
use xpallet_gateway_common::traits::{AddressBinding, ReferralBinding, TrusteeInfoUpdate};
use xpallet_gateway_records::ChainT;
use xpallet_support::try_str;

pub fn process_tx<T: Config>(
    tx: Transaction,
    prev_tx: Option<Transaction>,
    network: Network,
    min_deposit: u64,
    current_trustee_pair: (Address, Address),
    last_trustee_pair: Option<(Address, Address)>,
) -> BtcTxState {
    let btc_tx_detector = BtcTxTypeDetector::new(network, min_deposit);
    let meta_type = btc_tx_detector.detect_transaction_type::<T::AccountId, _>(
        &tx,
        prev_tx.as_ref(),
        T::AccountExtractor::extract_account,
        current_trustee_pair,
        last_trustee_pair,
    );

    let tx_type = meta_type.ref_into();
    let result = match meta_type {
        BtcTxMetaType::<_>::Deposit(deposit_info) => deposit::<T>(tx.hash(), deposit_info),
        BtcTxMetaType::<_>::Withdrawal => withdraw::<T>(tx),
        BtcTxMetaType::TrusteeTransition => trustee_transition::<T>(tx),
        BtcTxMetaType::HotAndCold => BtcTxResult::Success,
        // mark `Irrelevance` be `Failure` so that it could be replayed in the future
        BtcTxMetaType::<_>::Irrelevance => BtcTxResult::Failure,
    };

    BtcTxState { tx_type, result }
}

fn trustee_transition<T: Config>(tx: Transaction) -> BtcTxResult {
    let amount = tx.outputs().iter().map(|output| output.value).sum::<u64>();

    T::TrusteeInfoUpdate::update_transition_status(Chain::Bitcoin, false, Some(amount));

    BtcTxResult::Success
}

fn deposit<T: Config>(txid: H256, deposit_info: BtcDepositInfo<T::AccountId>) -> BtcTxResult {
    let account_info = match (deposit_info.op_return, deposit_info.input_addr) {
        (Some((account, referral)), Some(input_addr)) => {
            let input_addr = input_addr.to_string().into_bytes();
            // remove old unbinding deposit info
            remove_pending_deposit::<T>(&input_addr, &account);
            // update or override binding info
            T::AddressBinding::update_binding(Pallet::<T>::chain(), input_addr, account.clone());
            AccountInfo::<T::AccountId>::Account((account, referral))
        }
        (Some((account, referral)), None) => {
            // has opreturn but no input addr
            debug!(
                target: "runtime::bitcoin",
                "[deposit] Deposit tx ({:?}) has no input addr, but has opreturn, who:{:?}",
                hash_rev(txid),
                account
            );
            AccountInfo::<T::AccountId>::Account((account, referral))
        }
        (None, Some(input_addr)) => {
            // no opreturn but have input addr, use input addr to get accountid
            let addr_bytes = input_addr.to_string().into_bytes();
            match T::AddressBinding::address(Pallet::<T>::chain(), addr_bytes) {
                Some(account) => AccountInfo::Account((account, None)),
                None => AccountInfo::Address(input_addr),
            }
        }
        (None, None) => {
            warn!(
                target: "runtime::bitcoin",
                "[deposit] Process deposit tx ({:?}) but missing valid opreturn and input addr",
                hash_rev(txid)
            );
            return BtcTxResult::Failure;
        }
    };

    match account_info {
        AccountInfo::<_>::Account((account, referral)) => {
            T::ReferralBinding::update_binding(&T::BtcAssetId::get(), &account, referral);
            match deposit_token::<T>(txid, &account, deposit_info.deposit_value.saturated_into()) {
                Ok(_) => {
                    info!(
                        target: "runtime::bitcoin",
                        "[deposit] Deposit tx ({:?}) success, who:{:?}, balance:{}",
                        hash_rev(txid),
                        account,
                        deposit_info.deposit_value
                    );
                    BtcTxResult::Success
                }
                Err(_) => BtcTxResult::Failure,
            }
        }
        AccountInfo::<_>::Address(input_addr) => {
            insert_pending_deposit::<T>(&input_addr, txid, deposit_info.deposit_value);
            info!(
                target: "runtime::bitcoin",
                "[deposit] Deposit tx ({:?}) into pending, addr:{:?}, balance:{}",
                hash_rev(txid),
                try_str(input_addr.to_string().into_bytes()),
                deposit_info.deposit_value
            );
            BtcTxResult::Success
        }
    }
}

fn deposit_token<T: Config>(txid: H256, who: &T::AccountId, balance: T::Balance) -> DispatchResult {
    let asset_id = T::BtcAssetId::get();

    match pallet_assets::Pallet::<T>::mint_into(asset_id, who, balance) {
        Ok(()) => {
            Pallet::<T>::deposit_event(Event::<T>::Deposited(txid, who.clone(), balance));
            Ok(())
        }
        Err(err) => {
            error!(
                target: "runtime::bitcoin",
                "[deposit_token] Deposit error:{:?}, must use root to fix it",
                err
            );
            Err(err)
        }
    }
}

pub fn remove_pending_deposit<T: Config>(input_address: &BtcAddress, who: &T::AccountId) {
    // notice this would delete this cache
    let records = PendingDeposits::<T>::take(input_address);
    for record in records {
        // ignore error
        let _ = deposit_token::<T>(record.txid, who, record.balance.saturated_into());
        info!(
            target: "runtime::bitcoin",
            "[remove_pending_deposit] Use pending info to re-deposit, who:{:?}, balance:{}, cached_tx:{:?}",
            who, record.balance, record.txid,
        );

        Pallet::<T>::deposit_event(Event::<T>::PendingDepositRemoved(
            who.clone(),
            record.balance.saturated_into(),
            record.txid,
            input_address.clone(),
        ));
    }
}

fn insert_pending_deposit<T: Config>(input_addr: &Address, txid: H256, balance: u64) {
    let addr_bytes = input_addr.to_string().into_bytes();

    let cache = BtcDepositCache { txid, balance };

    PendingDeposits::<T>::mutate(&addr_bytes, |list| {
        if !list.contains(&cache) {
            log::debug!(
                target: "runtime::bitcoin",
                "[insert_pending_deposit] Add pending deposit, address:{:?}, txhash:{:?}, balance:{}",
                try_str(&addr_bytes),
                txid,
                balance
            );
            list.push(cache);

            Pallet::<T>::deposit_event(Event::<T>::UnclaimedDeposit(txid, addr_bytes.clone()));
        }
    });
}

fn withdraw<T: Config>(tx: Transaction) -> BtcTxResult {
    if let Some(proposal) = WithdrawalProposal::<T>::take() {
        log::debug!(
            target: "runtime::bitcoin",
            "[withdraw] Withdraw tx {:?}, proposal:{:?}",
            proposal,
            tx
        );
        let proposal_hash = proposal.tx.hash();
        let tx_hash = tx.hash();

        if proposal_hash == tx_hash {
            // Check if the transaction is normal witness
            let input = &tx.inputs()[0];
            if input.script_witness.len() != 3 {
                error!(
                    target: "runtime::bitcoin",
                    "[withdraw] Withdraw tx {:?} is not normal witness, proposal:{:?}",
                    tx,
                    proposal
                );
                return BtcTxResult::Failure;
            }

            let mut total = T::Balance::zero();
            for number in proposal.withdrawal_id_list.iter() {
                // just for event record
                let withdraw_balance =
                    xpallet_gateway_records::Pallet::<T>::pending_withdrawals(number)
                        .map(|record| record.balance())
                        .unwrap_or_else(T::Balance::zero);
                total += withdraw_balance;

                match xpallet_gateway_records::Pallet::<T>::finish_withdrawal(*number, None) {
                    Ok(_) => {
                        info!(target: "runtime::bitcoin", "[withdraw] Withdrawal ({}) completion", *number);
                    }
                    Err(err) => {
                        error!(
                            target: "runtime::bitcoin",
                            "[withdraw] Withdrawal ({}) error:{:?}, must use root to fix it",
                            *number, err
                        );
                    }
                }
            }

            let btc_withdrawal_fee = Pallet::<T>::btc_withdrawal_fee();
            // real withdraw value would reduce withdraw_fee
            total -=
                (proposal.withdrawal_id_list.len() as u64 * btc_withdrawal_fee).saturated_into();

            // Record trustee signature
            match T::TrusteeInfoUpdate::update_trustee_sig_record(
                Chain::Bitcoin,
                tx,
                total.saturated_into(),
            ) {
                Ok(_) => {
                    info!(target: "runtime::bitcoin", "[withdraw] Withdrawal tx ({:?}) sig record success.", tx_hash);
                }
                Err(err) => {
                    error!(target: "runtime::bitcoin", "[withdraw] Withdrawal tx ({:?}) sig record error:{:?}", tx_hash, err);
                }
            };

            Pallet::<T>::deposit_event(Event::<T>::Withdrawn(
                tx_hash,
                proposal.withdrawal_id_list,
                total,
            ));
            BtcTxResult::Success
        } else {
            error!(
                target: "runtime::bitcoin",
                "[withdraw] Withdraw error: mismatch (tx_hash:{:?}, proposal_hash:{:?}), id_list:{:?}, must use root to fix it",
                tx_hash, proposal_hash, proposal.withdrawal_id_list
            );
            // re-store proposal into storage.
            WithdrawalProposal::<T>::put(proposal);

            Pallet::<T>::deposit_event(Event::<T>::WithdrawalFatalErr(proposal_hash, tx_hash));
            BtcTxResult::Failure
        }
    } else {
        error!(
            target: "runtime::bitcoin",
            "[withdraw] Withdrawal error: proposal is EMPTY (tx_hash:{:?}), but receive a withdrawal tx, must use root to fix it",
            tx.hash()
        );
        // no proposal, but find a withdraw tx, it's a fatal error in withdrawal
        Pallet::<T>::deposit_event(Event::<T>::WithdrawalFatalErr(
            tx.hash(),
            Default::default(),
        ));

        BtcTxResult::Failure
    }
}
