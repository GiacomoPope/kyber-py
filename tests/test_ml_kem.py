import unittest
import json
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class TestML_KEM(unittest.TestCase):
    """
    Test ML_KEM levels for internal
    consistency by generating key pairs
    and shared secrets.
    """

    def generic_test_ML_KEM(self, ML_KEM, count):
        for _ in range(count):
            (ek, dk) = ML_KEM.keygen()
            for _ in range(count):
                (K, c) = ML_KEM.encaps(ek)
                K_prime = ML_KEM.decaps(dk, c)
                self.assertEqual(K, K_prime)

    def test_ML_KEM_512(self):
        self.generic_test_ML_KEM(ML_KEM_512, 5)

    def test_ML_KEM_768(self):
        self.generic_test_ML_KEM(ML_KEM_768, 5)

    def test_ML_KEM_1024(self):
        self.generic_test_ML_KEM(ML_KEM_1024, 5)

    def test_encaps_type_check_failure(self):
        """
        Send an ecaps key of the wrong length
        """
        self.assertRaises(ValueError, lambda: ML_KEM_512.encaps(b"1"))

    def test_encaps_modulus_check_failure(self):
        """
        We create a vector of polynomials with non-canonical values for
        coefficents to fail the modulus check
        """
        (ek, _) = ML_KEM_512.keygen()
        rho = ek[-32:]

        bad_f_hat = ML_KEM_512.R([3329] * 256)
        bad_t_hat = ML_KEM_512.M.vector([bad_f_hat, bad_f_hat])
        bad_t_hat_bytes = bad_t_hat.encode(12)

        bad_ek = bad_t_hat_bytes + rho

        self.assertEqual(len(bad_ek), len(ek))
        self.assertRaises(ValueError, lambda: ML_KEM_512.encaps(bad_ek))

    def test_xof_failure(self):
        self.assertRaises(
            ValueError, lambda: ML_KEM_512._xof(b"1", b"2", b"3")
        )

    def test_prf_failure(self):
        self.assertRaises(ValueError, lambda: ML_KEM_512._prf(2, b"1", b"2"))

    def test_decaps_ct_type_check_failure(self):
        """
        Send a ciphertext of the wrong length
        """
        ek, dk = ML_KEM_512.keygen()
        K, c = ML_KEM_512.encaps(ek)
        self.assertRaises(ValueError, lambda: ML_KEM_512.decaps(dk, b"1"))

    def test_decaps_dk_type_check_failure(self):
        """
        Send a ciphertext of the wrong length
        """
        ek, dk = ML_KEM_512.keygen()
        K, c = ML_KEM_512.encaps(ek)
        self.assertRaises(ValueError, lambda: ML_KEM_512.decaps(b"1", c))

    def test_decaps_hash_check_failure(self):
        """
        Send a ciphertext of the wrong length
        """
        ek, dk = ML_KEM_512.keygen()
        K, c = ML_KEM_512.encaps(ek)
        dk_bad = b"0" * len(dk)
        self.assertRaises(ValueError, lambda: ML_KEM_512.decaps(dk_bad, c))

    def test_derive_with_wrong_seed_length(self):
        with self.assertRaises(ValueError) as e:
            ML_KEM_512.key_derive(bytes(range(63)))

        self.assertIn("seed must be 64 bytes", str(e.exception))

    # test vectors copied from
    # https://datatracker.ietf.org/doc/html/draft-ietf-lamps-kyber-certificates-07
    def test_derive_from_seed_ML_KEM_512(self):
        ek, _ = ML_KEM_512.key_derive(bytes(range(64)))

        exp_ek = bytes.fromhex(
            """
            3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16
            c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f
            1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869
            dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d00
            0d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920f
            a213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d
            24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729
            535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a5418
            29a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc
            3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619
            be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797
            411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434
            c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b
            817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c7137
            76575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3
            c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859
            516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675a
            f41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed86
            81b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5
            af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f
            09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0
            b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b
            4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b
            4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723
            344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c
        """
        )

        self.assertEqual(len(ek), len(exp_ek))
        self.assertEqual(ek, exp_ek)

    def test_derive_from_seed_ML_KEM_768(self):
        ek, _ = ML_KEM_768.key_derive(bytes(range(64)))

        exp_ek = bytes.fromhex(
            """
            298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c
            cef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f7
            6531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f
            5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c6808052
            0a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832
            102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e
            972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d72
            90b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234
            d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516
            de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344c
            ab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736
            a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c
            4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6
            378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b
            530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5
            551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe236590036
            4d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c
            057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052
            db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2
            892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d
            986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b13850
            65e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc6
            5db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3
            e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a033
            5b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb1
            3a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438
            e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851c
            b8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1
            956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0
            ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e
            19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855
            c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812
            f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740
            abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c
            2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa
            8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d869
            5e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578
        """
        )

        self.assertEqual(len(ek), len(exp_ek))
        self.assertEqual(ek, exp_ek)

    def test_derive_from_seed_ML_KEM_1024(self):
        ek, _ = ML_KEM_1024.key_derive(bytes(range(64)))

        exp_ek = bytes.fromhex(
            """
            4b94c29450111191823b3514c9ac1ea3d9825ccb86393a2dfb04654fa2192d37
            bfad1c497c6502eee5ca80a73bfce0baf5a54a88585a401397a3d232f426a7af
            b082bc21a44317090eaac7592c2ea88a653c4491ea193931335f52e989a3c4cc
            56d9c553732d57c470fb41ab759b65d2d04445382fcd9c4e344a1128fa9e11e0
            4358e192ed014b23232a7ee2b22e23717f44111ee33575399c37646da9813ec9
            b212afe94e5dc5c2330a7294cc1f4234a6d3fbb4f1685ab8892c04acb17cd1c1
            70d7b0611b6a7176c794cc8c67f55fc923c2ad203100f365991882c30243d778
            13843b5ec7c964032263706092ecf00c7516be64e4598ca4226c069bb5e67e41
            75cf2286c8dd5c488a6c5861f31baa0bd0269470e8b551dd3bcd38c86c12f9cd
            b176c77dc8b6c02a701f478902c8553f694c0d82727b4c4a5c2c1041212aa127
            4808b82111b377ec75214e9b1978f76004d4139d98613f4b8e98d20af7b53407
            3a509a959b7a7564f9b40ca218bf61829320a8502017954d328d7ac6c769ec29
            700756e7b0685b340d5e118059504a49a9a50a10198eb10a5784678eb427d7b4
            babb9552933b062897973e1318eaf0a0eac37584a65401b1703e042accd83753
            1483f241cadcd1c1d378119e694429db199ac891e4c5343757085bb3ae783667
            350c4458d97672e861e80b1d2679510ea3a6f2360c77a46942c7a06a554d2280
            80c84b47aef14db17620cb16c06ab30a1be4cda7082be9f87e9c211c46916349
            a5ba8eaa5201c7294a3c0885b53b657452108825ec646c90a04612324ee7d031
            afe5343132cbef67b6efb1a5ec2809b773538ce77b3d8b04eb0b3c2256011e4c
            716c19a8ba0752bf71492117649f0615c3290fc29a46fde4bd52db9286d60338
            8244259c15a7ac2b640a60cc03376a5841a3fb8a473568fa9b1a267215f34c01
            697b0f0e627175d72105b7707c29b9e614bdc33a6f6c818a95370b427882d7b4
            76796a9ec6eb993274cd9b2391a82ba45e3393d2e9ae9721ca9d6c1b988b5827
            713f90a6585de9433528c02b03ce10bb5f720138d0fbb4c30c1266b918e52925
            dfe17b37f95d22bca54f475919ac859098c0f0d08ac5875ef29b56fd141e6ef1
            5f700a0b66f39595c588177373c4669b21bc071e4c3aa5f0b4a31b6258f35da2
            4ac3cd29c7f2092410c5078355b138fb53a6b9ae6e0b9c08243e7baa45c47376
            eb8c7f13d4cf51aa736fa31540c9241f370da544bf9f9c28d9a57e2f2a7ca95a
            4e4b466e641ab3bcc76adf1139d567a6f12b52f3a65e7ec0aae26bcaa8c55833
            b04e59998ebc9a1930fbb6d2233c53d2c1f8b9518e3c2de73a19dee6b380a5b3
            2971cf64e129fd6c1fa6e75d4a234501e966dd3a540af5c8f4f34a6b4a253ee2
            8492566d5e67c6f55855fcb0506fb06c156744d9a03a31a26fa94cad14f157b7
            f303d07a69c773768fcb4d079c09059703a0c3a94de4b99ea3a2f16583d0f917
            0a3950db07b4f0bc30802927f9f7961b6259892636a9502a2705303637799dd3
            44da451c1cf7bf67840ceb3079ab8c6b8c1927f64053c612450c45c9e603bc16
            666e596b3471e103b6f15447424d17022048111ffbd37e1c670f64f14b8a7b32
            b94c1a49b45dd2fc38cd5289d910ad63602cf5e13042c64ac6797b89fb551ad0
            8e05a92d200cccb7e712ef23c9312cb350f029ab537e287347fd3075ac10906a
            783f1c6c07ccb88f41228c4be1c640f790b5c3a5d5d3ca792495d74bc4615626
            58c07ac600276b924ab5bc9be1f0494cb76f82f460a7480972663381e1699960
            61d799859ec54d4f5ca5c411c01db1597b165977669de13a928a34afbac258fe
            a8c4764239c9421dc3119bf5b47699206978327b1c5345ef746a7983841f056e
            2534100ab24d4e9abbd0b17c6a95bd4c3c0e40f69e1612aceeb28b99086c9511
            6e7204273893390bf46b899b36286b0ebf1947bb9884f732ca27da82b19b5dc0
            cc7f8885714910888b2310c4f9319d410b34e6433b9003e2176bb99525745610
            6e8952163b8ba592530cc5aa0aeb43ad398fe9e97baa523d7a4431677c3d3af0
            719e475db85ca95af5089beabeb05b2faab4896ba60f81c88472a57b46a82882
            6a0cdfb446f8189182d2bf5eac4ec1cc5deaf599c8a13e48235406d17ffddc83
            44b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e1175
        """
        )

        self.assertEqual(len(ek), len(exp_ek))
        self.assertEqual(ek, exp_ek)


class TestML_KEM_KAT(unittest.TestCase):
    """
    Test ML-KEM against test vectors collected from
    https://github.com/usnistgov/ACVP-Server/releases/tag/v1.1.0.35
    """

    def generic_keygen_kat(self, ML_KEM, index):
        with open("assets/ML-KEM-keyGen-FIPS203/internalProjection.json") as f:
            data = json.load(f)
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            d_kat = bytes.fromhex(test["d"])
            z_kat = bytes.fromhex(test["z"])
            ek_kat = bytes.fromhex(test["ek"])
            dk_kat = bytes.fromhex(test["dk"])

            ek, dk = ML_KEM._keygen_internal(d_kat, z_kat)
            self.assertEqual(ek, ek_kat)
            self.assertEqual(dk, dk_kat)

    def generic_encap_kat(self, ML_KEM, index):
        with open(
            "assets/ML-KEM-encapDecap-FIPS203/internalProjection.json"
        ) as f:
            data = json.load(f)
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            ek_kat = bytes.fromhex(test["ek"])
            dk_kat = bytes.fromhex(test["dk"])
            c_kat = bytes.fromhex(test["c"])
            k_kat = bytes.fromhex(test["k"])
            m_kat = bytes.fromhex(test["m"])

            K, c = ML_KEM._encaps_internal(ek_kat, m_kat)
            self.assertEqual(K, k_kat)
            self.assertEqual(c, c_kat)

            K_prime = ML_KEM.decaps(dk_kat, c_kat)
            self.assertEqual(K_prime, k_kat)

    def generic_decap_kat(self, ML_KEM, index):
        with open(
            "assets/ML-KEM-encapDecap-FIPS203/internalProjection.json"
        ) as f:
            data = json.load(f)
        kat_data = data["testGroups"][3 + index]["tests"]

        # Parse out the decaps key
        dk_hex = data["testGroups"][3 + index]["dk"]
        dk_kat = bytes.fromhex(dk_hex)

        # Ensure that decaps works
        for test in kat_data:
            c_kat = bytes.fromhex(test["c"])
            k_kat = bytes.fromhex(test["k"])
            K = ML_KEM.decaps(dk_kat, c_kat)
            self.assertEqual(K, k_kat)

    def test_ML_KEM_512_keygen(self):
        self.generic_keygen_kat(ML_KEM_512, 0)

    def test_ML_KEM_768_keygen(self):
        self.generic_keygen_kat(ML_KEM_768, 1)

    def test_ML_KEM_1024_keygen(self):
        self.generic_keygen_kat(ML_KEM_1024, 2)

    def test_ML_KEM_512_encap(self):
        self.generic_encap_kat(ML_KEM_512, 0)

    def test_ML_KEM_768_encap(self):
        self.generic_encap_kat(ML_KEM_768, 1)

    def test_ML_KEM_1024_encap(self):
        self.generic_encap_kat(ML_KEM_1024, 2)

    def test_ML_KEM_512_decap(self):
        self.generic_decap_kat(ML_KEM_512, 0)

    def test_ML_KEM_768_decap(self):
        self.generic_decap_kat(ML_KEM_768, 1)

    def test_ML_KEM_1024_decap(self):
        self.generic_decap_kat(ML_KEM_1024, 2)
