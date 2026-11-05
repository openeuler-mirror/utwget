// OPIE (One-Time Passwords in Everything) 认证单元测试
//
// 注意: OPIE 功能需要启用 `ftp-opie` feature

#[cfg(feature = "ftp-opie")]
mod opie_tests {
    use ut_ftp::opie::{parse_opie_challenge, OpieAlgorithm, OpieChallenge, OpieResponse};

    // ========== OPIE Challenge 解析测试 ==========

    #[test]
    fn test_parse_opie_challenge_md5() {
        let prompt = "otp-md5 498 wi12345";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 498);
        assert_eq!(c.seed, "wi12345");
        assert_eq!(c.algorithm, OpieAlgorithm::Md5);
    }

    #[test]
    fn test_parse_opie_challenge_md4() {
        let prompt = "otp-md4 100 seed123";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 100);
        assert_eq!(c.seed, "seed123");
        assert_eq!(c.algorithm, OpieAlgorithm::Md4);
    }

    #[test]
    fn test_parse_opie_challenge_sha1() {
        let prompt = "otp-sha1 500 myseed";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 500);
        assert_eq!(c.seed, "myseed");
        assert_eq!(c.algorithm, OpieAlgorithm::Sha1);
    }

    #[test]
    fn test_parse_opie_challenge_skey() {
        // S/Key 格式
        let prompt = "s/key 99 foobar";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 99);
        assert_eq!(c.seed, "foobar");
    }

    #[test]
    fn test_parse_opie_challenge_with_colon() {
        // 某些服务器可能在种子后加冒号
        let prompt = "otp-md5 498 wi12345:";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 498);
        // 冒号应该被去除
        assert_eq!(c.seed, "wi12345");
    }

    #[test]
    fn test_parse_opie_challenge_with_prefix_text() {
        // 服务器可能在前面添加额外文本
        let prompt = "Using OTP authentication. otp-md5 498 wi12345";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 498);
        assert_eq!(c.seed, "wi12345");
    }

    #[test]
    fn test_parse_opie_challenge_invalid_no_otp() {
        let prompt = "regular password prompt";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_none());
    }

    #[test]
    fn test_parse_opie_challenge_invalid_no_sequence() {
        let prompt = "otp-md5 wi12345";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_none());
    }

    #[test]
    fn test_parse_opie_challenge_invalid_no_seed() {
        let prompt = "otp-md5 498";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_none());
    }

    #[test]
    fn test_parse_opie_challenge_empty() {
        let challenge = parse_opie_challenge("");
        assert!(challenge.is_none());
    }

    #[test]
    fn test_parse_opie_challenge_whitespace() {
        let prompt = "  otp-md5  498  wi12345  ";
        let challenge = parse_opie_challenge(prompt);
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.sequence, 498);
        assert_eq!(c.seed, "wi12345");
    }

    // ========== OPIE 算法测试 ==========

    #[test]
    fn test_opie_algorithm_equality() {
        assert_eq!(OpieAlgorithm::Md5, OpieAlgorithm::Md5);
        assert_ne!(OpieAlgorithm::Md5, OpieAlgorithm::Md4);
        assert_ne!(OpieAlgorithm::Md5, OpieAlgorithm::Sha1);
    }

    #[test]
    fn test_opie_algorithm_debug() {
        // 确保算法可以调试打印
        let alg = OpieAlgorithm::Md5;
        let debug_str = format!("{:?}", alg);
        assert!(debug_str.contains("Md5"));
    }

    #[test]
    fn test_opie_algorithm_clone() {
        let alg = OpieAlgorithm::Sha1;
        let cloned = alg.clone();
        assert_eq!(alg, cloned);
    }

    #[test]
    fn test_opie_algorithm_copy() {
        let alg = OpieAlgorithm::Md4;
        let copied = alg; // Copy 语义
        assert_eq!(alg, copied);
    }

    // ========== OPIE 响应计算测试 ==========

    #[test]
    fn test_opie_response_md5() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("password");
        assert!(response.is_some());
        let r = response.unwrap();
        // 响应应该是六词短语
        let words: Vec<&str> = r.response_hex.split_whitespace().collect();
        assert_eq!(words.len(), 6);
    }

    #[test]
    fn test_opie_response_md4() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md4,
        };
        let response = challenge.compute_response("password");
        assert!(response.is_some());
        let r = response.unwrap();
        let words: Vec<&str> = r.response_hex.split_whitespace().collect();
        assert_eq!(words.len(), 6);
    }

    #[test]
    fn test_opie_response_sha1() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Sha1,
        };
        let response = challenge.compute_response("password");
        assert!(response.is_some());
        let r = response.unwrap();
        let words: Vec<&str> = r.response_hex.split_whitespace().collect();
        assert_eq!(words.len(), 6);
    }

    #[test]
    fn test_opie_response_deterministic() {
        // 相同输入应该产生相同输出
        let challenge = OpieChallenge {
            sequence: 10,
            seed: "myseed".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let r1 = challenge.compute_response("mypass").unwrap();
        let r2 = challenge.compute_response("mypass").unwrap();
        assert_eq!(r1.response_hex, r2.response_hex);
    }

    #[test]
    fn test_opie_response_different_seeds() {
        // 不同种子应该产生不同响应
        let c1 = OpieChallenge {
            sequence: 1,
            seed: "seed1".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let c2 = OpieChallenge {
            sequence: 1,
            seed: "seed2".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let r1 = c1.compute_response("pass").unwrap();
        let r2 = c2.compute_response("pass").unwrap();
        assert_ne!(r1.response_hex, r2.response_hex);
    }

    #[test]
    fn test_opie_response_different_passwords() {
        // 不同密码应该产生不同响应
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let r1 = challenge.compute_response("pass1").unwrap();
        let r2 = challenge.compute_response("pass2").unwrap();
        assert_ne!(r1.response_hex, r2.response_hex);
    }

    #[test]
    fn test_opie_response_different_sequences() {
        // 不同序列号应该产生不同响应
        let c1 = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let c2 = OpieChallenge {
            sequence: 2,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let r1 = c1.compute_response("pass").unwrap();
        let r2 = c2.compute_response("pass").unwrap();
        assert_ne!(r1.response_hex, r2.response_hex);
    }

    #[test]
    fn test_opie_response_empty_password() {
        // 空密码也应该能计算响应
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("");
        assert!(response.is_some());
    }

    #[test]
    fn test_opie_response_high_sequence() {
        // 高序列号测试
        let challenge = OpieChallenge {
            sequence: 999,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("password");
        assert!(response.is_some());
    }

    // ========== OpieChallenge 结构体测试 ==========

    #[test]
    fn test_opie_challenge_debug() {
        let challenge = OpieChallenge {
            sequence: 100,
            seed: "myseed".to_string(),
            algorithm: OpieAlgorithm::Sha1,
        };
        let debug_str = format!("{:?}", challenge);
        assert!(debug_str.contains("100"));
        assert!(debug_str.contains("myseed"));
    }

    // ========== OpieResponse 结构体测试 ==========

    #[test]
    fn test_opie_response_debug() {
        let response = OpieResponse {
            response_hex: "word1 word2 word3 word4 word5 word6".to_string(),
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("word1"));
    }

    // ========== 边界情况测试 ==========

    #[test]
    fn test_opie_challenge_long_seed() {
        let long_seed = "a".repeat(100);
        let challenge = OpieChallenge {
            sequence: 1,
            seed: long_seed.clone(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("pass");
        assert!(response.is_some());
    }

    #[test]
    fn test_opie_challenge_special_chars_in_seed() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test-seed_123!@#".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("pass");
        assert!(response.is_some());
    }

    #[test]
    fn test_opie_challenge_unicode_seed() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "测试种子".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("pass");
        assert!(response.is_some());
    }

    #[test]
    fn test_opie_response_unicode_password() {
        let challenge = OpieChallenge {
            sequence: 1,
            seed: "test".to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let response = challenge.compute_response("密码测试");
        assert!(response.is_some());
    }

    // ========== 各种算法对比测试 ==========

    #[test]
    fn test_algorithms_produce_different_results() {
        let passphrase = "testpass";
        let seed = "testseed";

        let c_md4 = OpieChallenge {
            sequence: 1,
            seed: seed.to_string(),
            algorithm: OpieAlgorithm::Md4,
        };
        let c_md5 = OpieChallenge {
            sequence: 1,
            seed: seed.to_string(),
            algorithm: OpieAlgorithm::Md5,
        };
        let c_sha1 = OpieChallenge {
            sequence: 1,
            seed: seed.to_string(),
            algorithm: OpieAlgorithm::Sha1,
        };

        let r_md4 = c_md4.compute_response(passphrase).unwrap();
        let r_md5 = c_md5.compute_response(passphrase).unwrap();
        let r_sha1 = c_sha1.compute_response(passphrase).unwrap();

        // 三种算法应该产生不同的结果
        assert_ne!(r_md4.response_hex, r_md5.response_hex);
        assert_ne!(r_md5.response_hex, r_sha1.response_hex);
        assert_ne!(r_md4.response_hex, r_sha1.response_hex);
    }
}

// ========== 非 ftp-opie feature 时的测试 ==========

#[cfg(not(feature = "ftp-opie"))]
mod no_opie_tests {
    #[test]
    fn test_opie_feature_not_enabled() {
        // 当 ftp-opie feature 未启用时，此测试通过
        // 这确保了编译不会因缺少 OPIE 支持而失败
        assert!(true);
    }
