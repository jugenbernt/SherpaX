// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use frame_support::{assert_noop, assert_ok};

use light_bitcoin::{
    chain::{h256, BlockHeader},
    keys::Network,
    serialization,
};

use crate::{
    mock::{
        alice, generate_blocks_3782200_3782230, generate_blocks_478557_478563, ExtBuilder,
        XGatewayDogecoin, XGatewayDogecoinErr,
    },
    types::DogeHeaderIndex,
};

#[test]
fn test_genesis() {
    ExtBuilder::default().build_and_execute(|| {
        let (header, num) = XGatewayDogecoin::genesis_info();
        assert_eq!(
            header.hash(),
            h256("0xd1aa912454ed4ae5338f11cee503aa87d0baec5c0c5141848b3a50d763084578")
        );
        assert_eq!(num, 3782200);

        let index = XGatewayDogecoin::best_index();
        assert_eq!(
            index,
            DogeHeaderIndex {
                hash: header.hash(),
                height: 3782200
            }
        );
    })
}

#[test]
fn test_insert_headers() {
    let (base_height, c1, _) = generate_blocks_478557_478563();
    ExtBuilder::default()
        .build_mock((*c1.get(0).unwrap(), base_height), Network::Mainnet)
        .execute_with(|| {
            assert_noop!(
                XGatewayDogecoin::apply_push_header(*c1.get(0).unwrap()),
                XGatewayDogecoinErr::ExistingHeader
            );

            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(1).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(2).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(3).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(4).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(5).unwrap()));

            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(5).unwrap().hash());

            should_in_mainchain(&c1, true);
        })
}

fn should_in_mainchain(headers: &[BlockHeader], expect: bool) {
    for header in headers.iter() {
        assert_eq!(XGatewayDogecoin::main_chain(&header.hash()), expect);
    }
}

#[test]
fn test_insert_forked_headers_from_genesis_height() {
    // e.g.
    // b1
    // b --- b --- b --- b
    // |---- b --- b
    let (base_height, c1, forked) = generate_blocks_478557_478563();
    ExtBuilder::default()
        .build_mock((*c1.get(1).unwrap(), base_height + 1), Network::Mainnet)
        .execute_with(|| {
            // note: confirm block is 4
            assert_noop!(
                XGatewayDogecoin::apply_push_header(*c1.get(1).unwrap()),
                XGatewayDogecoinErr::ExistingHeader
            );

            // insert first
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(2).unwrap()));
            // best index is normal block 2
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(2).unwrap().hash());

            // insert forked first
            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(2).unwrap()));
            // contains two block at height 2, but best index still normal
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(2).unwrap().hash());
            should_in_mainchain(&c1[1..3], true);

            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(3).unwrap()));
            // forked block overtake than normal, change current best to forked 3
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, forked.get(3).unwrap().hash());
            assert_eq!(XGatewayDogecoin::confirmed_index(), None);
            should_in_mainchain(&c1[2..3], false);
            should_in_mainchain(&forked[1..4], true);

            // start insert normal
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(3).unwrap()));
            // because forked 3 insert before, so that even receive normal 3, best still forked 3
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, forked.get(3).unwrap().hash());

            // switch forked to normal chain
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(4).unwrap()));
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(4).unwrap().hash());
            // confirm set to 1
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(1).unwrap().hash());

            // move confirmed in normal chain
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(5).unwrap()));
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(5).unwrap().hash());
            // confirm set to 2
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(2).unwrap().hash());

            should_in_mainchain(&c1[1..6], true);
            should_in_mainchain(&forked[2..4], false);
            println!("current confirmed height:{:?}", confirmed_index.height);

            // add a forked block exceed confirmed height, this forked block would mark as AncientFork,
            // but now this forked block is less then best, so do not do confirmed check
            // and on the other hand, confirmed block for this forked block is before current normal
            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(4).unwrap()));
            // but when add a more forked block, would try to move confirmed
            assert_noop!(
                XGatewayDogecoin::apply_push_header(*forked.get(5).unwrap()),
                XGatewayDogecoinErr::AncientFork,
            );
        })
}

#[test]
fn test_insert_forked_headers() {
    // e.g.
    // b0
    // b --- b --- b --- b --- b
    //       |---- b --- b
    let (base_height, c1, forked) = generate_blocks_478557_478563();
    ExtBuilder::default()
        .build_mock((*c1.get(0).unwrap(), base_height), Network::Mainnet)
        .execute_with(|| {
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(1).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(2).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(3).unwrap()));
            should_in_mainchain(&c1[0..4], true);
            // now confirmed would set
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(0).unwrap().hash());

            // insert forked
            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(2).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(3).unwrap()));
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(3).unwrap().hash());
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(0).unwrap().hash());
            should_in_mainchain(&c1[0..4], true);
            should_in_mainchain(&forked[2..4], false);

            // insert forked, switch chain, but confirm b1, b1 is also the parent for normal chain
            assert_ok!(XGatewayDogecoin::apply_push_header(*forked.get(4).unwrap()));
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, forked.get(4).unwrap().hash());
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(1).unwrap().hash());
            should_in_mainchain(&c1[2..4], false);
            should_in_mainchain(&forked[1..5], true);

            // b1 still on normal chain, so we could switch to normal and reset main chain
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(4).unwrap()));
            assert_ok!(XGatewayDogecoin::apply_push_header(*c1.get(5).unwrap()));
            let best_index = XGatewayDogecoin::best_index();
            assert_eq!(best_index.hash, c1.get(5).unwrap().hash());
            let confirmed_index = XGatewayDogecoin::confirmed_index().unwrap();
            assert_eq!(confirmed_index.hash, c1.get(2).unwrap().hash());
            should_in_mainchain(&c1[0..6], true);
            should_in_mainchain(&forked[2..5], false);
        });
}

#[test]
fn test_change_difficulty() {
    ExtBuilder::default().build_and_execute(|| {
        let headers = generate_blocks_3782200_3782230();
        let to_height = 3782200 + 20;
        let current_difficulty = headers[&3782201].bits;
        let new_difficulty = headers[&to_height].bits;
        println!(
            "current_difficulty: bit:{:?}|new_difficulty: bit:{:?}",
            current_difficulty, new_difficulty
        );
        for i in 3782201..to_height {
            assert_ok!(XGatewayDogecoin::apply_push_header(headers[&i]));
        }
    })
}

#[test]
fn test_call() {
    ExtBuilder::default().build_and_execute(|| {
        let headers = generate_blocks_3782200_3782230();
        let origin = frame_system::RawOrigin::Signed(alice()).into();
        let v = serialization::serialize(&headers[&(3782200 + 1)]);
        let v = v.take();
        assert_ok!(XGatewayDogecoin::push_header(origin, v));
    })
}