/** @file
 *****************************************************************************
 *  Interface of a digital signature with free choice of used edwards curve
 *
 *  Template parameter ppT enables user to choose between various Curves,
 *  however, only Edwards curves are supported.
 *  Signatures are compatible with PureEdDSA gadget in ethsnarks library,
 *  when G is set to inner curve ("jubjub") of proving system
 *  (libff::G1<ethsnarks:default_inner_ec_pp>)
 *
 *  Algorithm EdDSA with Poseidon Hash on a custom Edwards Cuve
 *****************************************************************************/

#ifndef SIGNATURE_EDDSA_SNARKFRIENDLY_HPP
#define SIGNATURE_EDDSA_SNARKFRIENDLY_HPP

#include <memory>
#include <vector>
#include <stdexcept>

#include <libff/algebra/curves/public_params.hpp>

namespace libsnark {

template<typename ppT>
class eddsa_sf_signature;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_signature<ppT> &signature);

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_signature<ppT> &signature);

template<typename ppT>
class eddsa_sf_signature {
public:
    libff::G1<ppT> R;
    libff::Fr<ppT> s;

    eddsa_sf_signature() {};
    eddsa_sf_signature(libff::G1<ppT> R, libff::Fr<ppT> s) : R(R), s(s) {};
    eddsa_sf_signature& operator=(const eddsa_sf_signature &other) = default;
    eddsa_sf_signature(const eddsa_sf_signature &other) = default;
    eddsa_sf_signature(eddsa_sf_signature &&other) = default;

    size_t G1_size() const
    {
        return 1;
    }

    size_t Fr_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
            + Fr_size() * libff::Fr<ppT>::ceil_size_in_bits();
    }

    size_t size_in_bytes() const
    {
        return (size_in_bits() + 7) / 8; // ceil size_in_bits() / 8
    }

    bool is_well_formed() const
    {
        return R.is_well_formed();
    }

    bool operator==(const eddsa_sf_signature &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const eddsa_sf_signature &signature);
    friend std::istream& operator>> <ppT>(std::istream &in, eddsa_sf_signature &signature);
};

template<typename ppT>
class eddsa_sf_pubkey;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_pubkey<ppT> &pubkey);

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_pubkey<ppT> &pubkey);

template<typename ppT>
class eddsa_sf_pubkey {
public:
     libff::G1<ppT> pkey;

    eddsa_sf_pubkey() {};
    eddsa_sf_pubkey(libff::G1<ppT> pkey) : pkey(pkey) {};
    eddsa_sf_pubkey& operator=(const eddsa_sf_pubkey &other) = default;
    eddsa_sf_pubkey(const eddsa_sf_pubkey &other) = default;
    eddsa_sf_pubkey(eddsa_sf_pubkey &&other) = default;

    size_t G1_size() const
    {
        return 1;
    }

    size_t Fr_size() const
    {
        return 0;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
            + Fr_size() * libff::Fr<ppT>::ceil_size_in_bits();
    }

    size_t size_in_bytes() const
    {
        return (size_in_bits() + 7) / 8; // ceil size_in_bits() / 8
    }

    bool operator==(const eddsa_sf_pubkey &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const eddsa_sf_pubkey &pubkey);
    friend std::istream& operator>> <ppT>(std::istream &in, eddsa_sf_pubkey &pubkey);
};

template<typename ppT>
class eddsa_sf_privkey;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_privkey<ppT> &privkey);

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_privkey<ppT> &privkey);

template<typename ppT>
class eddsa_sf_privkey {
public:
    libff::Fr<ppT> pkey;

    eddsa_sf_privkey() {};
    eddsa_sf_privkey(libff::Fr<ppT> pkey) : pkey(pkey) {};
    eddsa_sf_privkey& operator=(const eddsa_sf_privkey &other) = default;
    eddsa_sf_privkey(const eddsa_sf_privkey &other) = default;
    eddsa_sf_privkey(eddsa_sf_privkey &&other) = default;

    size_t G1_size() const
    {
        return 0;
    }

    size_t Fr_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
            + Fr_size() * libff::Fr<ppT>::ceil_size_in_bits();
    }

    size_t size_in_bytes() const
    {
        return (size_in_bits() + 7) / 8; // ceil size_in_bits() / 8
    }

    bool operator==(const eddsa_sf_privkey &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const eddsa_sf_privkey &privkey);
    friend std::istream& operator>> <ppT>(std::istream &in, eddsa_sf_privkey &privkey);
};

template<typename ppT>
class eddsa_sf_keypair;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_keypair<ppT> &keypair);

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_keypair<ppT> &keypair);

template<typename ppT>
class eddsa_sf_keypair {
public:
    eddsa_sf_pubkey<ppT> pubkey;
    eddsa_sf_privkey<ppT> privkey;

    eddsa_sf_keypair() = default;
    eddsa_sf_keypair& operator=(const eddsa_sf_keypair<ppT> &other) = default;
    eddsa_sf_keypair(const eddsa_sf_keypair &other) = default;
    eddsa_sf_keypair(eddsa_sf_pubkey<ppT> &&pubkey, eddsa_sf_privkey<ppT> &&privkey):
        pubkey(std::move(pubkey)),
        privkey(std::move(privkey))
    {};
    eddsa_sf_keypair(eddsa_sf_keypair &&other) = default;

    size_t G1_size() const
    {
        return pubkey.G1_size() + privkey.G1_size();
    }

    size_t Fr_size() const
    {
        return pubkey.Fr_size() + privkey.Fr_size();
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
            + Fr_size() * libff::Fr<ppT>::ceil_size_in_bits();
    }

    size_t size_in_bytes() const
    {
        return (size_in_bits() + 7) / 8; // ceil size_in_bits() / 8
    }

    bool operator==(const eddsa_sf_keypair &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const eddsa_sf_keypair<ppT> &keypair);
    friend std::istream& operator>> <ppT>(std::istream &in, eddsa_sf_keypair<ppT> &keypair);

};

template<typename ppT>
eddsa_sf_keypair<ppT> eddsa_sf_generate();

template<typename ppT, typename PoseidonParametersT> // ppT is curve for signature, so usually it is the inner (jubjub) curve, if one plans to prove the verification of such a signature inside a SNARK
eddsa_sf_signature<ppT> eddsa_poseidon_sign(const PoseidonParametersT &param, const eddsa_sf_privkey<ppT> &privkey, const std::vector<libff::Fq<ppT>> &msg);

template<typename ppT> // ppT is curve for signature, so usually it is the inner (jubjub) curve, if one plans to prove the verification of such a signature inside a SNARK
eddsa_sf_signature<ppT> eddsa_pedersen_sign(const eddsa_sf_privkey<ppT> &privkey, const std::vector<uint8_t> &msg);

template<typename ppT, typename PoseidonParametersT>
bool eddsa_poseidon_verify(const PoseidonParametersT &param, const eddsa_sf_pubkey<ppT> &pubkey, const eddsa_sf_signature<ppT> &signature, const std::vector<libff::Fq<ppT>> &msg);

template<typename ppT>
bool eddsa_pedersen_verify(const eddsa_sf_pubkey<ppT> &pubkey, const eddsa_sf_signature<ppT> &signature, const std::vector<uint8_t> &msg);

}

#include <libsnark/common/crypto/signature/eddsa_snarkfriendly.tcc>

#endif //SIGNATURE_EDDSA_SNARKFRIENDLY_HPP
