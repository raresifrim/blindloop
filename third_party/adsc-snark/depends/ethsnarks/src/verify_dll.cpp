#include "stubs.hpp"

extern "C" {

bool ethsnarks_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}

}
