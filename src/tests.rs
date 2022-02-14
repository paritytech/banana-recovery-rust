#[cfg(test)]
mod tests {
    use hex;

    use crate::shares::{generate_logs_and_exps, MAX_BITS, MIN_BITS};
    use crate::{NextAction, Share, ShareSet};

    const SECRET_SEEDPHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    // scanned qr codes for Alice seed phrase, 3 shares generated
    const SCAN_A1: &str = "7b2276223a312c2274223a22416c6963652074726965732042616e616e6153706c697420616761696e222c2272223a322c2264223a223841666c74524d465a42425930326b3675457262364e747a375855364957796747764649444c4247566167542f6e7a5365507a55304e7a436e7175795975363765666634675462674564445542787671594f4d32557048326c6758544c673667583437546c694958554d66317562322f7675726c7479727769516b564e5636505158673d3d222c226e223a226f39446270426939723755574a484f726975444172523456726330564f6f336c227d";
    const SCAN_A2: &str = "7b2276223a312c2274223a22416c6963652074726965732042616e616e6153706c697420616761696e222c2272223a322c2264223a223841752f61694a2b794343786f715a7843434d6e32312f426358675a4b4935316b55742b644a6d6f782f7255456c3434485149547a437055414a38516835635a302b7155717067554d76697161777238763671786d3959544f4e636e66667942774249693067634b576f776463776f31664270456b5176357757694358654f38486a773d3d222c226e223a226f39446270426939723755574a484f726975444172523456726330564f6f336c227d";
    const SCAN_A3: &str = "7b2276223a312c2274223a22416c6963652074726965732042616e616e6153706c697420616761696e222c2272223a322c2264223a2238417861337a4637724444706363394c743952667969422f4b587a372f43775778434b516349454f6d6564716d5a424e776e75744636766157584e79394a425553683263732f32372f2b4e51594e58644370486a444d644d6357614c544b31696d575a787768762b6f4a6c4735557450456d596e6f4f73433155674d716c69424b77413d3d222c226e223a226f39446270426939723755574a484f726975444172523456726330564f6f336c227d";
    const PASSPHRASE_A: &str = "blighted-comprised-bucktooth-disjoin";

    // scanned qr codes for another secret, also 3 shares generated
    const SCAN_B1: &str = "7b2276223a312c2274223a227465727269626c655c2274727574685c5c5c226573636170696e67222c2272223a322c2264223a2238415553374d6556585855746f6d4e75744a5a55794d3571776f43553978484e527754335a7855345634772f6b2b7a392b326e4f4e53755041635039786d74313766413d3d222c226e223a2232657364784b536243436b4b4b59626b63465269446b692b2b5447304e5a6258227d";
    const SCAN_B2: &str = "7b2276223a312c2274223a227465727269626c655c2274727574685c5c5c226573636170696e67222c2272223a322c2264223a2238416f687259746575757062514c617448536a646e47594f6a5a63314347614f514a6359373163376c39766565425a4a477734644c6c4c4b63784352744833546b55513d3d222c226e223a2232657364784b536243436b4b4b59626b63465269446b692b2b5447304e5a6258227d";
    const SCAN_B3: &str = "7b2276223a312c2274223a227465727269626c655c2274727574685c5c5c226573636170696e67222c2272223a322c2264223a223841387a51557a4c35353932347458447162364a553948395a4a7057635568676b6557526c4c6b5731446c524470414b6c5079414a336e616f714732536c784f5253673d3d222c226e223a2232657364784b536243436b4b4b59626b63465269446b692b2b5447304e5a6258227d";
    const PASSPHRASE_B: &str = "clapping-deskbound-carving-compress";
    const SECRET_B: &str = "it was the butler!";

    // scanned qr codes for same Alice seed phrase, 5 shares generated
    const SCAN_C1: &str = "7b2276223a312c2274223a22616c6963652068617320746f6f206d616e7920667269656e6473222c2272223a332c2264223a2238416639685249636c676879765935706f4178535a59317664546c79625a37324862354e494d536f686257334e44477139477462552f514e32577130704b505a754a6a6c344d586c7a6e636e4e787a567743493367686f682f377a686b4544682f376c725654587445716a5066424e48652b3867575a76757761617944335744454d673d3d222c226e223a22774c4a2b4b31663456654955784a6a7051736f6c724864725a49645a61657176227d";
    const SCAN_C2: &str = "7b2276223a312c2274223a22616c6963652068617320746f6f206d616e7920667269656e6473222c2272223a332c2264223a2238416f4e556549754463476641597134496c4e496c513159493653785162673075694e5963517965536c645a50786d766b754d76586c326a377333424c2f505461505a782b6a436c704e4c49314c366b79776b7a6f6f6f386236333550394171316376345655526b7959464b774a2b434875414a3471334d525156686a7830676369773d3d222c226e223a22774c4a2b4b31663456654955784a6a7051736f6c724864725a49645a61657176227d";
    const SCAN_C3: &str = "7b2276223a312c2274223a22616c6963652068617320746f6f206d616e7920667269656e6473222c2272223a332c2264223a2238413377315041796d386e7476415452687430336552396a50327946447259333935726b72555a71556d514d66545a7247464d74722b486a3266673532785855567243782f564a7a706c6e792b414966557a367249686d6a765530335a42543161694d332f5172654c58736450674f676d784e446b714466306d7551764431394943413d3d222c226e223a22774c4a2b4b31663456654955784a6a7051736f6c724864725a49645a61657176227d";
    const PASSPHRASE_C: &str = "appetizer-deserving-accompany-cusp";

    #[test]
    fn alice_recovers_secret1() {
        let share1 = Share::new(hex::decode(SCAN_A1).unwrap()).unwrap();
        let mut share_set = ShareSet::init(share1);
        assert!(
            share_set.next_action() == NextAction::MoreShares { have: 1, need: 2 },
            "Single share is not enough."
        );

        let share1_again = Share::new(hex::decode(SCAN_A1).unwrap()).unwrap();
        assert!(
            share_set.try_add_share(share1_again).is_err(),
            "Can not add the same share second time."
        );

        let share2 = Share::new(hex::decode(SCAN_A2).unwrap()).unwrap();
        share_set.try_add_share(share2).unwrap();
        assert!(
            share_set.next_action() == NextAction::AskPwd,
            "Two different shares are sufficient."
        );

        let alice_secret = share_set.recover_with_passphrase(PASSPHRASE_A).unwrap();
        assert!(alice_secret == SECRET_SEEDPHRASE, "Unexpected secret!");
    }

    #[test]
    fn alice_recovers_secret2() {
        let share1 = Share::new(hex::decode(SCAN_A1).unwrap()).unwrap();
        let mut share_set = ShareSet::init(share1);
        let share3 = Share::new(hex::decode(SCAN_A3).unwrap()).unwrap();
        share_set.try_add_share(share3).unwrap();
        let alice_secret = share_set.recover_with_passphrase(PASSPHRASE_A).unwrap();
        assert!(alice_secret == SECRET_SEEDPHRASE, "Unexpected secret!");
    }

    #[test]
    fn alice_recovers_secret3() {
        let share2 = Share::new(hex::decode(SCAN_A2).unwrap()).unwrap();
        let mut share_set = ShareSet::init(share2);
        let share3 = Share::new(hex::decode(SCAN_A3).unwrap()).unwrap();
        share_set.try_add_share(share3).unwrap();
        let alice_secret = share_set.recover_with_passphrase(PASSPHRASE_A).unwrap();
        assert!(alice_secret == SECRET_SEEDPHRASE, "Unexpected secret!");
    }

    #[test]
    fn alice_makes_weird_title() {
        // scanned qr code, with nasty title
        let maybe_share = Share::new(hex::decode(SCAN_B1).unwrap());
        assert!(maybe_share.is_ok(), "Should be parsed normally");
        let share_set = ShareSet::init(maybe_share.unwrap());
        let title = share_set.title();
        assert!(
            title == r#"terrible"truth\"escaping"#,
            "Got different title: \n{}",
            title
        );
    }

    #[test]
    fn alice_recovers_secret4() {
        // escaping has to be removed properly, since the title is used to generate salt
        let share2 = Share::new(hex::decode(SCAN_B2).unwrap()).unwrap();
        let mut share_set = ShareSet::init(share2);
        let share3 = Share::new(hex::decode(SCAN_B3).unwrap()).unwrap();
        share_set.try_add_share(share3).unwrap();
        let alice_secret = share_set.recover_with_passphrase(PASSPHRASE_B).unwrap();
        assert!(
            alice_secret == SECRET_B,
            "Unexpected secret! Found secret: \n{}",
            alice_secret
        );
    }

    #[test]
    fn alice_recovers_secret5() {
        let share1 = Share::new(hex::decode(SCAN_C1).unwrap()).unwrap();
        let mut share_set = ShareSet::init(share1);
        let share2 = Share::new(hex::decode(SCAN_C2).unwrap()).unwrap();
        share_set.try_add_share(share2).unwrap();
        assert!(
            share_set.next_action() == NextAction::MoreShares { have: 2, need: 3 },
            "Two shares not enough this time."
        );
        let share3 = Share::new(hex::decode(SCAN_C3).unwrap()).unwrap();
        share_set.try_add_share(share3).unwrap();
        let alice_secret = share_set.recover_with_passphrase(PASSPHRASE_C).unwrap();
        assert!(alice_secret == SECRET_SEEDPHRASE, "Unexpected secret!");
    }

    #[test]
    fn math_works_as_expected() {
        // checking that logs generation is done properly
        for n in MIN_BITS..=MAX_BITS {
            let (logs, _) = generate_logs_and_exps(n);
            for (i, x) in logs.iter().enumerate() {
                if i == 0 {
                    assert!(x.is_none(), "log[0] should remain undefined")
                } else {
                    assert!(x.is_some(), "log[i] should be determined for i != 0")
                }
            }
        }
    }
}
